"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.status import Status as RichStatus

from . import __copyright__, __version__, env_check, report
from .engine import Reporter, TriageEngine, TriageOptions
from .models import Cancelled, Finding, Status
from .report import TriageResult
from .review import ReviewStore
from .virustotal import VTResult
from .whitelist import WhitelistError

EXIT_OK, EXIT_ENV, EXIT_DETECTED, EXIT_INTERRUPTED = 0, 1, 2, 130

console = Console(highlight=False)


# ----------------------------------------------------------------- argumentos
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="win11-triage",
        description="Triaje defensivo de Windows 11 con Sysinternals + VirusTotal.",
        epilog="Códigos de salida: 0 sin detecciones · 1 entorno incompleto · 2 detecciones en VT · 130 interrumpido.",
    )
    mod = p.add_argument_group("módulos")
    mod.add_argument("--autoruns", action="store_true", help="auditoría de persistencia (autorunsc)")
    mod.add_argument(
        "--scan-user",
        action="store_true",
        help=r"ejecutables/DLL sin firma en %%LOCALAPPDATA%%\Temp y %%APPDATA%% (sigcheck)",
    )
    mod.add_argument("--processes", action="store_true", help="procesos en ejecución sospechosos (psutil)")
    mod.add_argument(
        "--events",
        nargs="?",
        const=7,
        type=int,
        metavar="DÍAS",
        help="eventos 7045/4698 y detecciones de Defender de los últimos DÍAS (por defecto 7)",
    )
    mod.add_argument(
        "--sigma",
        action="store_true",
        help="aplica reglas Sigma a Sysmon, 4688, PowerShell 4104 y 7045 (usa los días de --events)",
    )
    mod.add_argument(
        "--browsers", action="store_true", help="extensiones de Chrome, Edge, Brave y Firefox (permisos y origen)"
    )
    mod.add_argument("--network", action="store_true", help="conexiones activas por PID (psutil; tcpvcon de respaldo)")
    mod.add_argument(
        "--static", action="store_true", help="análisis de contenido: PE (pefile) y YARA si está instalado"
    )
    mod.add_argument("--vt", action="store_true", help="consulta los SHA-256 en VirusTotal (requiere VT_API_KEY)")
    mod.add_argument(
        "--intel",
        action="store_true",
        help="reputación de IPs (AbuseIPDB) y hashes (MalwareBazaar); claves en .env",
    )
    mod.add_argument("--all", action="store_true", help="activa todos los módulos")

    opt = p.add_argument_group("opciones")
    opt.add_argument("--gui", action="store_true", help="abre la interfaz gráfica")
    opt.add_argument(
        "--dry-run", action="store_true", help="usa datos de ejemplo: no ejecuta herramientas ni usa la red"
    )
    opt.add_argument("--vt-limit", type=int, metavar="N", help="máximo de consultas nuevas a VT en esta ejecución")
    opt.add_argument(
        "--config-dir",
        type=Path,
        metavar="DIR",
        help="carpeta con .env, whitelist.json y vt_cache.json (por defecto: WIN11_TRIAGE_HOME o la actual)",
    )
    opt.add_argument(
        "--output-dir", type=Path, metavar="DIR", help="carpeta de informes (por defecto: <config-dir>/reportes)"
    )
    opt.add_argument(
        "--format",
        choices=report.FORMAT_CHOICES,
        default="md",
        help="formato del informe: md, html, json, both (md+json) o all (por defecto: md)",
    )
    opt.add_argument("--no-report", action="store_true", help="no exportar informe")
    opt.add_argument(
        "--evidence",
        action="store_true",
        help="genera además un paquete de evidencias .zip (informes, CSV, IoC, SHA256SUMS)",
    )
    opt.add_argument("--min-score", type=int, metavar="N", help="muestra e informa solo los elementos con score ≥ N")
    opt.add_argument(
        "--fail-on-score",
        type=int,
        metavar="N",
        help="código de salida 2 si algún elemento tiene score ≥ N (además de las detecciones de VT)",
    )
    al = p.add_argument_group("alertas e integraciones")
    al.add_argument("--notify", action="store_true", help="notificación de Windows al terminar")
    al.add_argument(
        "--webhook",
        metavar="URL",
        default=None,
        help="envía el resumen a Slack, Teams, Splunk HEC o JSON genérico (por defecto: WIN11_TRIAGE_WEBHOOK)",
    )
    al.add_argument("--jsonl", type=Path, metavar="FICHERO", help="añade los hallazgos en JSON Lines (Wazuh, Filebeat)")
    al.add_argument(
        "--alert-new",
        action="store_true",
        help="alerta solo de lo nuevo o lo que empeora respecto al análisis anterior",
    )
    al.add_argument(
        "--schedule",
        choices=("daily", "weekly", "off", "status"),
        help="programa un análisis diario o semanal con alertas de novedades (off: lo quita)",
    )
    al.add_argument("--at", default="09:00", metavar="HH:MM", help="hora del análisis programado (por defecto 09:00)")
    opt.add_argument(
        "--explain", action="store_true", help="«¿Qué hago con esto?»: pasos recomendados para los 5 más graves"
    )
    opt.add_argument("--check-update", action="store_true", help="comprueba si hay una versión nueva y sale")
    opt.add_argument("--no-color", action="store_true", help="desactiva los colores")
    opt.add_argument(
        "-v", "--verbose", action="store_true", help="muestra comandos ejecutados y detalles de depuración"
    )
    opt.add_argument("--version", action="version", version=f"%(prog)s {__version__} · {__copyright__}")
    return p


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = build_parser()
    a = p.parse_args(argv)
    if a.vt_limit is not None and a.vt_limit < 0:
        p.error("--vt-limit debe ser >= 0")
    modules = ("autoruns", "scan_user", "processes", "sigma", "browsers", "network", "static", "vt", "intel")
    if a.all or (a.dry_run and not any(getattr(a, m) for m in modules) and a.events is None):
        for m in modules:
            setattr(a, m, True)
        a.events = a.events or 7
    a.options = TriageOptions(
        autoruns=a.autoruns,
        scan_user=a.scan_user,
        processes=a.processes,
        events=a.events is not None,
        sigma=a.sigma,
        browsers=a.browsers,
        event_days=a.events or 7,
        static=a.static,
        network=a.network,
        vt=a.vt,
        intel=a.intel,
        dry_run=a.dry_run,
        vt_limit=a.vt_limit,
        config_dir=a.config_dir,
    )
    a.config_dir = a.options.config_dir
    a.output_dir = a.output_dir or a.config_dir / "reportes"
    return a


# ----------------------------------------------------------------- reporter
class RichReporter(Reporter):
    def __init__(self) -> None:
        self._status: RichStatus | None = None

    def stage(self, text: str) -> None:
        if self._status is None:
            self._status = console.status(text)
            self._status.start()
        else:
            self._status.update(text)

    def done(self) -> None:
        if self._status is not None:
            self._status.stop()
            self._status = None

    def info(self, text: str) -> None:
        console.print(text)

    def warn(self, text: str) -> None:
        console.print(f"[yellow]{text}[/]")

    def error(self, text: str) -> None:
        console.print(f"[red]{text}[/]")

    def vt_start(self, total: int, cached: int, new: int, eta: float) -> None:
        extra = f" (≈{eta / 60:.1f} min)" if eta else ""
        console.print(f"\nVirusTotal: {total} hashes únicos · {cached} en caché · {new} consultas nuevas{extra}")

    def vt_progress(self, index: int, total: int, sha256: str, result: VTResult, origin: str) -> None:
        self.done()
        f = Finding("", "", "", "", "", "", vt=result)
        console.print(f"  [{index}/{total}] {sha256[:16]}… → [{f.status.style}]{f.vt_summary}[/] [dim]({origin})[/]")

    def vt_wait(self, remaining: float) -> None:
        self.stage(f"[cyan]Límite de VirusTotal: esperando {remaining:4.1f}s…")


# ----------------------------------------------------------------- salida
def show_env(tools: dict[str, env_check.ToolStatus], needed: set[str], hints: bool = True) -> bool:
    console.print(report.env_table(tools))
    if not hints:
        console.print("[dim]Dry-run: las herramientas que falten no son necesarias.[/]")
        return True
    ok = True
    for name, st in tools.items():
        if st.found:
            continue
        required = name in needed
        ok &= not required
        color = "red" if required else "yellow"
        console.print(
            Panel(
                env_check.install_hint(name),
                title=f"[{color}]Falta {name}[/] — necesaria para {env_check.TOOLS[name]['used_by']}",
                title_align="left",
                border_style=color,
            )
        )
    return ok


def print_results(res: TriageResult) -> None:
    console.print()
    if report.top_findings(res.findings):
        console.print(report.priority_table(res.findings))
        console.print()
    if report.attack_summary(res.findings):
        console.print(report.attack_table(res.findings))
        console.print()
    for title, fs in res.sections.items():
        console.print(report.findings_table(f"{title} ({len(fs)})", fs))
        console.print()
    if any(f.connections for f in res.findings):
        console.print(report.connections_table([f for f in res.findings if f.connections]))
        console.print()
    c = res.counts()
    console.print(
        Panel(
            f"[bold red]{c[Status.DETECTED]} detectados[/]  ·  "
            f"[yellow]{c[Status.UNKNOWN]} sin firma / desconocidos[/]  ·  "
            f"[green]{c[Status.CLEAN]} limpios[/]  ·  [dim]{res.whitelisted} en lista blanca[/]",
            title="Resumen",
            title_align="left",
            border_style="red" if c[Status.DETECTED] else "green",
        )
    )


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)],
        force=True,
    )


# ----------------------------------------------------------------- main
def run(args: argparse.Namespace) -> int:
    opts: TriageOptions = args.options
    load_dotenv(opts.config_dir / ".env")  # type: ignore[operator]
    console.rule(f"[bold cyan]win11-triage {__version__}[/]" + ("  [yellow](DRY-RUN)[/]" if opts.dry_run else ""))

    windows, admin = env_check.is_windows(), env_check.is_admin()
    if not windows and not opts.dry_run:
        console.print("[yellow]Este sistema no es Windows: solo --dry-run es funcional aquí.[/]")
    elif windows and not admin and not opts.dry_run:
        console.print("[yellow]Sin privilegios de administrador: autoruns no verá todas las ubicaciones.[/]")

    tools = env_check.check_all()
    needed = {n for n, on in (("autorunsc.exe", opts.autoruns), ("sigcheck.exe", opts.scan_user)) if on}
    env_ok = show_env(tools, needed, hints=not opts.dry_run)

    if not opts.any_collector:
        console.print(
            "\nElige módulos: [bold]--autoruns --scan-user --processes --events --sigma --browsers --network --static --vt --intel[/] "
            "o [bold]--all[/]. También: [bold]--gui[/] (ayuda: --help)."
        )
        return EXIT_OK if env_ok else EXIT_ENV
    if not opts.dry_run and not (env_ok and windows):
        console.print("[red]No se puede continuar: faltan herramientas necesarias.[/]")
        return EXIT_ENV

    reporter = RichReporter()
    try:
        res = TriageEngine(opts, tools, reporter).run()
    except WhitelistError as e:
        console.print(f"[red]{e}[/]")
        return EXIT_ENV
    finally:
        reporter.done()

    if args.min_score is not None:
        hidden = sum(1 for f in res.findings if f.score < args.min_score)
        res.sections = {t: [f for f in fs if f.score >= args.min_score] for t, fs in res.sections.items()}
        console.print(f"[dim]--min-score {args.min_score}: {hidden} elemento(s) por debajo ocultos.[/]")

    review_store = ReviewStore(opts.config_dir)  # type: ignore[arg-type]
    res.reviews = review_store.data
    print_results(res)
    if not args.no_report:
        for path in report.write_reports(res, args.output_dir, args.format):
            console.print(f"[bold]Informe:[/] {path}")
    if args.evidence:
        zip_path = report.write_evidence_zip(res, args.output_dir / f"{res.file_stem}_evidencias.zip")
        console.print(f"[bold]Paquete de evidencias:[/] {zip_path}")

    if args.explain:
        print_explain(res)
    send_alerts(args, res)

    if opts.dry_run:
        return EXIT_OK  # el dry-run solo valida la estructura
    over = args.fail_on_score is not None and any(f.score >= args.fail_on_score for f in res.findings)
    return EXIT_DETECTED if (res.counts()[Status.DETECTED] or over) else EXIT_OK


def print_explain(res: TriageResult) -> None:
    from . import playbook

    top = [f for f in report.sort_findings(res.findings) if f.status != Status.CLEAN][:5]
    for f in top:
        adv = playbook.advice_for(f)
        steps = "\n".join(f"  {i}. {s}" for i, s in enumerate(adv.steps, 1))
        console.print(
            Panel(
                f"[bold]{adv.summary}[/]\n{steps}",
                title=f"¿Qué hago con esto? · {f.name} (score {f.score})",
                title_align="left",
                border_style="red" if f.status == Status.DETECTED else "yellow",
            )
        )


def send_alerts(args: argparse.Namespace, res: TriageResult) -> None:
    """--notify, --webhook y --jsonl; con --alert-new solo lo nuevo o lo que empeora."""
    webhook = args.webhook or os.environ.get("WIN11_TRIAGE_WEBHOOK", "").strip()
    if not (args.notify or webhook or args.jsonl):
        return
    from . import alerts, history

    previous = None
    if args.alert_new:
        current = args.output_dir / f"{res.file_stem}.json"
        prev = history.previous_of(history.list_reports(args.output_dir), current, res.started, res.dry_run)
        if prev is not None:
            with contextlib.suppress(OSError, ValueError, KeyError):
                previous = report.load_json(prev.path)
        if previous is None:
            console.print("[dim]--alert-new: no hay análisis anterior; se alerta de todo lo relevante.[/]")
    items = alerts.select_alertable(res, previous, only_new=args.alert_new and previous is not None)
    if args.jsonl:
        n = alerts.write_jsonl(args.jsonl, res, items)
        console.print(f"[bold]JSONL:[/] {n} evento(s) añadidos a {args.jsonl}")
    if not items and args.alert_new:
        console.print("[green]Sin novedades: no se envían alertas.[/]")
        return
    title, body = alerts.summary_text(res, items, args.alert_new)
    if args.notify and not alerts.notify_toast(f"win11-triage · {title}", body):
        console.print("[dim]Notificación de Windows no disponible en este sistema.[/]")
    if webhook:
        if res.dry_run:
            console.print(f"[dim]Dry-run: no se envía el webhook ({alerts.webhook_kind(webhook)}).[/]")
            return
        try:
            kind = alerts.send_webhook(webhook, res, items, args.alert_new)
            console.print(f"[bold]Webhook:[/] enviado ({kind}, {len(items)} elemento(s)).")
        except requests.RequestException as e:
            console.print(f"[yellow]No se pudo enviar el webhook: {e}[/]")


def schedule(args: argparse.Namespace) -> int:
    from . import scheduler

    try:
        if args.schedule == "status":
            console.print(scheduler.status())
        elif args.schedule == "off":
            scheduler.delete()
            console.print("Análisis programado eliminado.")
        else:
            script = scheduler.create(args.config_dir, args.schedule, args.at, admin=env_check.is_admin())
            when = "cada día" if args.schedule == "daily" else "cada lunes"
            console.print(f"[green]Programado {when} a las {args.at}.[/] Script: {script}")
            console.print("[dim]Solo avisará si hay hallazgos nuevos o que empeoran (--alert-new).[/]")
    except (RuntimeError, OSError, ValueError) as e:
        console.print(f"[red]No se pudo programar: {e}[/]")
        return EXIT_ENV
    return EXIT_OK


def check_update() -> int:
    import requests

    from .updates import check_latest

    try:
        info = check_latest()
    except requests.RequestException as e:
        console.print(f"[yellow]No se pudo comprobar: {e}[/]")
        return EXIT_ENV
    if info.available:
        console.print(f"[green]Hay una versión nueva: {info.latest}[/] (tienes {info.current}) → {info.url}")
    else:
        console.print(f"Tienes la última versión ({info.current}).")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    global console
    for stream in (sys.stdout, sys.stderr):
        # Consolas/pipes con cp1252 en Windows: evita UnicodeEncodeError con ─ → …
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = parse_args(argv)
    if args.check_update:
        return check_update()
    if args.schedule:
        return schedule(args)
    if args.gui:
        from .gui import main as gui_main

        return gui_main(args.config_dir)
    if args.no_color:
        console = Console(no_color=True, highlight=False)
    setup_logging(args.verbose)
    try:
        return run(args)
    except (KeyboardInterrupt, Cancelled):
        console.print("\n[yellow]Interrumpido por el usuario.[/]")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
