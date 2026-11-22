"""Punto de entrada de la CLI."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from . import __version__, collectors, env_check, report
from .models import DETECTED, Finding
from .virustotal import VTAuthError, VTClient
from .whitelist import Whitelist

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES = BASE_DIR / "samples"
console = Console()


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="win11-triage",
        description="Triaje defensivo de Windows 11 con Sysinternals + VirusTotal.",
    )
    p.add_argument("--autoruns", action="store_true", help="auditoría de persistencia (autorunsc)")
    p.add_argument("--scan-user", action="store_true", help="escanea %%LOCALAPPDATA%%\\Temp y %%APPDATA%% (sigcheck)")
    p.add_argument("--vt", action="store_true", help="consulta los hashes sospechosos en VirusTotal")
    p.add_argument("--all", action="store_true", help="equivale a --autoruns --scan-user --vt")
    p.add_argument("--dry-run", action="store_true", help="usa datos de ejemplo: no ejecuta herramientas ni usa la red")
    p.add_argument("--output-dir", type=Path, default=BASE_DIR / "reportes", help="carpeta de informes")
    p.add_argument("--no-report", action="store_true", help="no exportar el informe Markdown")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)
    if a.all:
        a.autoruns = a.scan_user = a.vt = True
    if a.dry_run and not (a.autoruns or a.scan_user or a.vt):
        a.autoruns = a.scan_user = a.vt = True
    if a.vt and not (a.autoruns or a.scan_user):
        a.autoruns = a.scan_user = True  # --vt necesita hallazgos de los que partir
    return a


def show_env(tools: dict, needed: set[str]) -> bool:
    console.print(report.env_table(tools))
    ok = True
    for name, st in tools.items():
        if st.found:
            continue
        info = env_check.TOOLS[name]
        required = name in needed
        ok &= not required
        console.print(
            Panel(
                env_check.install_hint(name),
                title=f"[{'red' if required else 'yellow'}]Falta {name}[/] — usado por {info['used_by']}",
                border_style="red" if required else "yellow",
            )
        )
    return ok


# ----------------------------------------------------------------- dry-run
def _dry_autoruns() -> list[Finding]:
    text = (SAMPLES / "autorunsc_sample.csv").read_text(encoding="utf-8")
    # Se pasa por UTF-16 para ejercitar el mismo decodificador que con autorunsc real.
    return collectors.parse_autoruns(collectors.decode_output(text.encode("utf-16")))


def _dry_sigcheck() -> list[Finding]:
    text = (SAMPLES / "sigcheck_sample.csv").read_text(encoding="utf-8")
    return collectors.parse_sigcheck(collectors.decode_output(text.encode("utf-8")), "(muestra)")


def _dry_vt_simulator():
    data = json.loads((SAMPLES / "vt_responses.json").read_text(encoding="utf-8"))
    return lambda h: data.get(h, {"found": False})


# ----------------------------------------------------------------- main
def main(argv=None) -> int:
    args = parse_args(argv)
    load_dotenv(BASE_DIR / ".env")
    console.rule(f"[bold cyan]win11-triage {__version__}[/]" + ("  [yellow](DRY-RUN)[/]" if args.dry_run else ""))

    is_windows = platform.system() == "Windows"
    if not is_windows and not args.dry_run:
        console.print("[yellow]Aviso: no es Windows. Solo --dry-run es funcional aquí.[/]")

    needed = set()
    if args.autoruns:
        needed.add("autorunsc.exe")
    if args.scan_user:
        needed.add("sigcheck.exe")
    tools = env_check.check_all()
    env_ok = show_env(tools, needed)

    if not (args.autoruns or args.scan_user):
        console.print("\nUsa [bold]--autoruns[/], [bold]--scan-user[/], [bold]--vt[/] o [bold]--all[/]. Ayuda: --help")
        return 0 if env_ok else 1
    if not args.dry_run and (not env_ok or not is_windows):
        console.print("[red]No se puede continuar: faltan herramientas necesarias.[/]")
        return 1

    wl_file = SAMPLES / "whitelist_sample.json" if args.dry_run else BASE_DIR / "whitelist.json"
    whitelist = Whitelist.load(wl_file)
    sections: dict[str, list[Finding]] = {}
    whitelisted = 0
    modules = []

    if args.autoruns:
        modules.append("autoruns")
        with console.status("Ejecutando autorunsc (puede tardar varios minutos)…"):
            found = _dry_autoruns() if args.dry_run else collectors.collect_autoruns(tools["autorunsc.exe"].path)
        found, n = whitelist.filter(found)
        whitelisted += n
        sections["Persistencia (Autoruns) — no Microsoft / no verificado"] = found

    if args.scan_user:
        modules.append("scan-user")
        found = []
        if args.dry_run:
            found = _dry_sigcheck()
        else:
            for folder in collectors.user_scan_targets():
                if not folder.is_dir():
                    continue
                with console.status(f"sigcheck sobre {folder}…"):
                    try:
                        found += collectors.collect_sigcheck(tools["sigcheck.exe"].path, folder)
                    except Exception as e:  # noqa: BLE001
                        console.print(f"[red]Error escaneando {folder}: {e}[/]")
        found, n = whitelist.filter(found)
        whitelisted += n
        sections["Rutas de usuario (Sigcheck) — sin firma válida"] = found

    vt_stats = None
    if args.vt:
        modules.append("vt")
        vt_stats = run_vt(args, [f for fs in sections.values() for f in fs])

    all_f = [f for fs in sections.values() for f in fs]
    console.print()
    for title, fs in sections.items():
        console.print(report.findings_table(f"{title} ({len(fs)})", fs))
    c = report.summary_counts(all_f)
    console.print(
        f"\n[bold]Resumen:[/] [bold red]{c['DETECTADO']} detectados[/] · "
        f"[yellow]{c['DESCONOCIDO']} sin firma/desconocidos[/] · "
        f"[green]{c['LIMPIO']} limpios[/] · [dim]{whitelisted} en lista blanca[/]"
    )

    if not args.no_report:
        meta = {
            "host": platform.node() or "host",
            "user": getpass.getuser(),
            "modules": modules,
            "whitelisted": whitelisted,
            "vt_stats": vt_stats,
            "dry_run": args.dry_run,
        }
        out = report.write_markdown(args.output_dir, tools, sections, meta)
        console.print(f"[bold]Informe:[/] {out}")

    if args.dry_run:
        return 0  # el dry-run solo valida la estructura
    return 2 if c[DETECTED] else 0


def run_vt(args, findings: list[Finding]) -> dict | None:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not args.dry_run and (not api_key or api_key == "pon_aqui_tu_api_key"):
        console.print("[yellow]VT_API_KEY no definida en .env: se omite VirusTotal (ver .env.example).[/]")
        return None
    client = VTClient(
        api_key=api_key or "dry-run",
        cache_file=BASE_DIR / "vt_cache.json",
        console=console,
        interval=0 if args.dry_run else 15,
        simulator=_dry_vt_simulator() if args.dry_run else None,
        persist=not args.dry_run,
    )
    hashes = sorted({f.sha256 for f in findings if f.sha256})
    console.print(f"\nVirusTotal: {len(hashes)} hashes únicos (los de caché no consumen cuota).")
    results = {}
    try:
        for i, h in enumerate(hashes, 1):
            r = client.lookup(h)
            results[h] = r
            src = "caché" if r.get("cached") else ("simulado" if args.dry_run else "API")
            console.print(f"  [{i}/{len(hashes)}] {h[:16]}… → {Finding('', '', '', '', '', '', vt=r).vt_summary} [dim]({src})[/]")
    except VTAuthError as e:
        console.print(f"[red]VirusTotal: {e}[/]")
    except KeyboardInterrupt:
        console.print("[yellow]Consulta VT interrumpida; se usan los resultados obtenidos.[/]")
    finally:
        client.save()
    for f in findings:
        if f.sha256 in results:
            f.vt = results[f.sha256]
    return client.stats


if __name__ == "__main__":
    sys.exit(main())
