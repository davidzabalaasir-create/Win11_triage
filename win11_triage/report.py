"""Salida en terminal (Rich) y exportación a Markdown."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import CLEAN, DETECTED, STATUS_STYLE, UNKNOWN, Finding

ORDER = {DETECTED: 0, UNKNOWN: 1, CLEAN: 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (ORDER[f.status], f.source, f.name.lower()))


def findings_table(title: str, findings: list[Finding]) -> Table:
    t = Table(title=title, title_style="bold", show_lines=False, expand=True)
    t.add_column("Estado", no_wrap=True)
    t.add_column("Nombre", overflow="fold", max_width=28)
    t.add_column("Ruta", overflow="fold", ratio=3)
    t.add_column("Editor / Firma", overflow="fold", ratio=2)
    t.add_column("SHA-256", no_wrap=True)
    t.add_column("VT", no_wrap=True, justify="right")
    for f in sort_findings(findings):
        style = STATUS_STYLE[f.status]
        t.add_row(
            f"[{style}]{f.status}[/]",
            f.name,
            f.path or "—",
            f"{f.publisher}\n[dim]{f.signature}[/]",
            (f.sha256[:16] + "…") if f.sha256 else "[dim]n/d[/]",
            f"[{style}]{f.vt_summary}[/]",
            style=None,
        )
    return t


def env_table(tools: dict) -> Table:
    t = Table(title="Comprobación de entorno", title_style="bold")
    t.add_column("Herramienta")
    t.add_column("Estado")
    t.add_column("Ubicación", overflow="fold")
    for name, st in tools.items():
        if st.found:
            t.add_row(name, "[green]OK[/]", f"{st.path} [dim]({st.origin})[/]")
        else:
            t.add_row(name, "[red]NO ENCONTRADA[/]", "—")
    return t


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    c = {DETECTED: 0, UNKNOWN: 0, CLEAN: 0}
    for f in findings:
        c[f.status] += 1
    return c


# ------------------------------------------------------------------ Markdown
def _md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


ICON = {DETECTED: "🔴", UNKNOWN: "🟡", CLEAN: "🟢"}


def write_markdown(
    out_dir: Path,
    tools: dict,
    sections: dict[str, list[Finding]],
    meta: dict,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "_dryrun" if meta.get("dry_run") else ""
    path = out_dir / f"triage_{meta.get('host', 'host')}_{stamp}{suffix}.md"

    all_f = [f for fs in sections.values() for f in fs]
    counts = summary_counts(all_f)
    L: list[str] = []
    L.append(f"# Informe win11-triage — {meta.get('host', '')}")
    L.append("")
    if meta.get("dry_run"):
        L.append("> **DRY-RUN**: datos de ejemplo, sin ejecutar herramientas ni consultar la red.")
        L.append("")
    L.append(f"- **Fecha:** {datetime.now():%Y-%m-%d %H:%M:%S}")
    L.append(f"- **Usuario:** {meta.get('user', '')}")
    L.append(f"- **Módulos:** {', '.join(meta.get('modules', [])) or 'ninguno'}")
    L.append(f"- **Elementos en lista blanca ignorados:** {meta.get('whitelisted', 0)}")
    if meta.get("vt_stats"):
        s = meta["vt_stats"]
        L.append(
            f"- **VirusTotal:** {s['network']} consultas nuevas, {s['cache']} desde caché, {s['errors']} errores"
        )
    L.append("")
    L.append("## Resumen")
    L.append("")
    L.append("| Estado | Total |")
    L.append("|---|---|")
    for k in (DETECTED, UNKNOWN, CLEAN):
        L.append(f"| {ICON[k]} {k} | {counts[k]} |")
    L.append("")
    L.append("## Entorno")
    L.append("")
    L.append("| Herramienta | Estado | Ruta |")
    L.append("|---|---|---|")
    for name, st in tools.items():
        L.append(f"| {name} | {'OK' if st.found else 'NO ENCONTRADA'} | `{st.path or '—'}` |")
    L.append("")

    for title, findings in sections.items():
        L.append(f"## {title} ({len(findings)})")
        L.append("")
        if not findings:
            L.append("_Sin hallazgos._")
            L.append("")
            continue
        L.append("| Estado | Nombre | Ruta | Editor | Firma | VT |")
        L.append("|---|---|---|---|---|---|")
        for f in sort_findings(findings):
            L.append(
                f"| {ICON[f.status]} {f.status} | {_md(f.name)} | `{_md(f.path)}` | "
                f"{_md(f.publisher)} | {_md(f.signature)} | {_md(f.vt_summary)} |"
            )
        L.append("")
        L.append("### Detalle")
        L.append("")
        for f in sort_findings(findings):
            L.append(f"#### {ICON[f.status]} {_md(f.name)}")
            L.append("")
            L.append(f"- **Ruta:** `{f.path or '—'}`")
            if f.location:
                L.append(f"- **Ubicación:** `{f.location}`")
            if f.category:
                L.append(f"- **Categoría:** {f.category}")
            L.append(f"- **Editor:** {f.publisher}")
            L.append(f"- **Firma:** {f.signature}")
            L.append(f"- **SHA-256:** `{f.sha256 or 'n/d'}`")
            if f.vt:
                v = f.vt
                if v.get("found"):
                    L.append(
                        f"- **VirusTotal:** {v.get('malicious', 0)} maliciosos, "
                        f"{v.get('suspicious', 0)} sospechosos de {v.get('total', 0)} motores"
                        + (f" — etiqueta: `{v['label']}`" if v.get("label") else "")
                    )
                    if v.get("link"):
                        L.append(f"- **Enlace:** {v['link']}")
                else:
                    L.append(f"- **VirusTotal:** {f.vt_summary}")
            L.append("")

    path.write_text("\n".join(L), encoding="utf-8")
    return path
