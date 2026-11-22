"""Punto de entrada de la CLI."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import platform
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

from . import __version__, collectors, env_check, report
from .models import Finding, Status
from .report import TriageResult
from .virustotal import VTAuthError, VTClient, VTResult
from .whitelist import Whitelist, WhitelistError

SAMPLES = Path(__file__).resolve().parent / "samples"
PLACEHOLDER_KEY = "pon_aqui_tu_api_key"

EXIT_OK, EXIT_ENV, EXIT_DETECTED, EXIT_INTERRUPTED = 0, 1, 2, 130

SECTION_AUTORUNS = "Persistencia (Autoruns) — no Microsoft / no verificado"
SECTION_SIGCHECK = "Rutas de usuario (Sigcheck) — sin firma válida"

console = Console(highlight=False)
log = logging.getLogger("win11_triage")


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
    mod.add_argument("--network", action="store_true", help="correlaciona hallazgos con conexiones activas (tcpvcon)")
    mod.add_argument("--vt", action="store_true", help="consulta los SHA-256 en VirusTotal (requiere VT_API_KEY)")
    mod.add_argument("--all", action="store_true", help="activa todos los módulos")

    opt = p.add_argument_group("opciones")
    opt.add_argument(
        "--dry-run", action="store_true", help="usa datos de ejemplo: no ejecuta herramientas ni usa la red"
    )
    opt.add_argument("--vt-limit", type=int, metavar="N", help="máximo de consultas nuevas a VT en esta ejecución")
    opt.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="carpeta con .env, whitelist.json y vt_cache.json (por defecto: WIN11_TRIAGE_HOME o la actual)",
    )
    opt.add_argument(
        "--output-dir", type=Path, metavar="DIR", help="carpeta de informes (por defecto: <config-dir>/reportes)"
    )
    opt.add_argument(
        "--format", choices=("md", "json", "both"), default="md", help="formato del informe (por defecto: md)"
    )
    opt.add_argument("--no-report", action="store_true", help="no exportar informe")
    opt.add_argument("--no-color", action="store_true", help="desactiva los colores")
    opt.add_argument(
        "-v", "--verbose", action="store_true", help="muestra los comandos ejecutados y detalles de depuración"
    )
    opt.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = build_parser()
    a = p.parse_args(argv)
    if a.vt_limit is not None and a.vt_limit < 0:
        p.error("--vt-limit debe ser >= 0")
    if a.all or (a.dry_run and not (a.autoruns or a.scan_user or a.network or a.vt)):
        a.autoruns = a.scan_user = a.network = a.vt = True
    if (a.vt or a.network) and not (a.autoruns or a.scan_user):
        a.autoruns = a.scan_user = True  # VT y red necesitan hallazgos de los que partir
    a.config_dir = (a.config_dir or Path(os.environ.get("WIN11_TRIAGE_HOME", Path.cwd()))).resolve()
    a.output_dir = a.output_dir or a.config_dir / "reportes"
    return a


# ----------------------------------------------------------------- entorno
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


# ----------------------------------------------------------------- dry-run
def _sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def _dry_autoruns() -> list[Finding]:
    # Se pasa por UTF-16 para ejercitar el mismo decodificador que con autorunsc real.
    return collectors.parse_autoruns(collectors.decode_output(_sample("autorunsc_sample.csv").encode("utf-16")))


def _dry_sigcheck() -> list[Finding]:
    return collectors.parse_sigcheck(_sample("sigcheck_sample.csv"), "(muestra)")


def _dry_vt_simulator() -> Callable[[str], VTResult]:
    data = json.loads(_sample("vt_responses.json"))
    return lambda h: dict(data.get(h, {"found": False}))


# ----------------------------------------------------------------- módulos
def run_autoruns(args: argparse.Namespace, res: TriageResult) -> list[Finding]:
    if args.dry_run:
        return _dry_autoruns()
    with console.status("Ejecutando autorunsc (puede tardar varios minutos)…"):
        return collectors.collect_autoruns(res.tools["autorunsc.exe"].path)  # type: ignore[arg-type]


def run_sigcheck(args: argparse.Namespace, res: TriageResult) -> list[Finding]:
    if args.dry_run:
        return _dry_sigcheck()
    found: list[Finding] = []
    for folder in collectors.user_scan_targets():
        if not folder.is_dir():
            log.debug("Carpeta inexistente, se omite: %s", folder)
            continue
        with console.status(f"Ejecutando sigcheck sobre {folder}…"):
            try:
                found += collectors.collect_sigcheck(res.tools["sigcheck.exe"].path, folder)  # type: ignore[arg-type]
            except collectors.CollectorError as e:
                res.errors.append(str(e))
                console.print(f"[red]{e}[/]")
    return found


def run_network(args: argparse.Namespace, res: TriageResult) -> None:
    if args.dry_run:
        conns = collectors.parse_tcpvcon(_sample("tcpvcon_sample.csv"))
    else:
        exe = res.tools["tcpvcon.exe"].path
        if exe is None:
            res.errors.append("tcpvcon.exe no encontrado: se omite --network")
            return
        try:
            conns = collectors.collect_tcpvcon(exe)
        except collectors.CollectorError as e:
            res.errors.append(str(e))
            console.print(f"[red]{e}[/]")
            return
    res.connections = conns
    matched = collectors.correlate_connections(res.findings, conns)
    console.print(f"Red: {len(conns)} conexiones activas · {matched} hallazgo(s) con conexiones.")


def run_vt(args: argparse.Namespace, res: TriageResult) -> None:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not args.dry_run and api_key in ("", PLACEHOLDER_KEY):
        msg = "VT_API_KEY no definida en .env: se omite VirusTotal (ver .env.example)."
        res.errors.append(msg)
        console.print(f"[yellow]{msg}[/]")
        return

    client = VTClient(
        api_key=api_key or "dry-run",
        cache_file=args.config_dir / "vt_cache.json",
        console=console,
        interval=0 if args.dry_run else 15,
        simulator=_dry_vt_simulator() if args.dry_run else None,
        persist=not args.dry_run,
    )
    hashes = sorted({f.sha256 for f in res.findings if f.sha256})
    pending = [h for h in hashes if not client.cached(h)]
    limit = len(pending) if args.vt_limit is None else min(args.vt_limit, len(pending))
    eta = max(0, limit - 1) * client.interval
    console.print(
        f"\nVirusTotal: {len(hashes)} hashes únicos · {len(hashes) - len(pending)} en caché · "
        f"{limit} consultas nuevas" + (f" (≈{eta / 60:.1f} min)" if eta else "")
    )

    results: dict[str, VTResult] = {}
    new_queries = 0
    try:
        for i, h in enumerate(hashes, 1):
            if h in pending:
                if new_queries >= limit:
                    client.stats["skipped"] += 1
                    continue
                new_queries += 1
            r = client.lookup(h)
            results[h] = r
            origin = "caché" if r.get("cached") else ("simulado" if args.dry_run else "API")
            summary = Finding("", "", "", "", "", "", vt=r)
            console.print(
                f"  [{i}/{len(hashes)}] {h[:16]}… → [{summary.status.style}]{summary.vt_summary}[/] [dim]({origin})[/]"
            )
    except VTAuthError as e:
        res.errors.append(f"VirusTotal: {e}")
        console.print(f"[red]VirusTotal: {e}[/]")
    finally:
        client.save()
        for f in res.findings:
            f.vt = results.get(f.sha256, f.vt)
        res.vt_stats = client.stats


# ----------------------------------------------------------------- salida
def print_results(res: TriageResult) -> None:
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
    )


# ----------------------------------------------------------------- main
def run(args: argparse.Namespace) -> int:
    load_dotenv(args.config_dir / ".env")
    console.rule(f"[bold cyan]win11-triage {__version__}[/]" + ("  [yellow](DRY-RUN)[/]" if args.dry_run else ""))

    windows, admin = env_check.is_windows(), env_check.is_admin()
    if not windows and not args.dry_run:
        console.print("[yellow]Este sistema no es Windows: solo --dry-run es funcional aquí.[/]")
    elif windows and not admin and not args.dry_run:
        console.print("[yellow]Sin privilegios de administrador: autoruns no verá todas las ubicaciones.[/]")

    needed = {n for n, flag in (("autorunsc.exe", args.autoruns), ("sigcheck.exe", args.scan_user)) if flag}
    tools = env_check.check_all()
    env_ok = show_env(tools, needed, hints=not args.dry_run)

    if not (args.autoruns or args.scan_user):
        console.print(
            "\nElige un módulo: [bold]--autoruns[/], [bold]--scan-user[/], [bold]--network[/], [bold]--vt[/] o [bold]--all[/] (ayuda: --help)."
        )
        return EXIT_OK if env_ok else EXIT_ENV
    if not args.dry_run and not (env_ok and windows):
        console.print("[red]No se puede continuar: faltan herramientas necesarias.[/]")
        return EXIT_ENV

    try:
        wl_file = SAMPLES / "whitelist_sample.json" if args.dry_run else args.config_dir / "whitelist.json"
        whitelist = Whitelist.load(wl_file, create=not args.dry_run)
    except WhitelistError as e:
        console.print(f"[red]{e}[/]")
        return EXIT_ENV

    res = TriageResult(
        host=platform.node() or "host",
        user=getpass.getuser(),
        started=datetime.now(),
        dry_run=args.dry_run,
        admin=admin,
        tools=tools,
    )

    collectors_to_run = (
        ("autoruns", args.autoruns, SECTION_AUTORUNS, run_autoruns),
        ("scan-user", args.scan_user, SECTION_SIGCHECK, run_sigcheck),
    )
    for module, enabled, section, fn in collectors_to_run:
        if not enabled:
            continue
        res.modules.append(module)
        try:
            found = fn(args, res)
        except collectors.CollectorError as e:
            res.errors.append(str(e))
            console.print(f"[red]{e}[/]")
            found = []
        found, skipped = whitelist.filter(found)
        res.whitelisted += skipped
        res.sections[section] = found

    if args.network:
        res.modules.append("network")
        run_network(args, res)
    if args.vt:
        res.modules.append("vt")
        run_vt(args, res)

    print_results(res)
    if not args.no_report:
        for path in report.write_reports(res, args.output_dir, args.format):
            console.print(f"[bold]Informe:[/] {path}")

    if args.dry_run:
        return EXIT_OK  # el dry-run solo valida la estructura
    return EXIT_DETECTED if res.counts()[Status.DETECTED] else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    global console
    for stream in (sys.stdout, sys.stderr):
        # Consolas/pipes con cp1252 en Windows: evita UnicodeEncodeError con ─ → …
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = parse_args(argv)
    if args.no_color:
        console = Console(no_color=True, highlight=False)
    setup_logging(args.verbose)
    try:
        return run(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/]")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
