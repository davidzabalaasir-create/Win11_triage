"""Salida en terminal (Rich) y exportación a Markdown / JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.table import Table

from . import __version__
from .env_check import ToolStatus
from .models import Connection, Finding, Status


@dataclass
class TriageResult:
    host: str
    user: str
    started: datetime
    dry_run: bool
    admin: bool
    tools: dict[str, ToolStatus]
    modules: list[str] = field(default_factory=list)
    sections: dict[str, list[Finding]] = field(default_factory=dict)
    connections: list[Connection] = field(default_factory=list)
    whitelisted: int = 0
    vt_stats: dict[str, int] | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for fs in self.sections.values() for f in fs]

    def counts(self) -> dict[Status, int]:
        c = dict.fromkeys(Status, 0)
        for f in self.findings:
            c[f.status] += 1
        return c

    @property
    def file_stem(self) -> str:
        suffix = "_dryrun" if self.dry_run else ""
        return f"triage_{self.host}_{self.started:%Y%m%d_%H%M%S}{suffix}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.status.rank, f.source, f.name.lower()))


# ------------------------------------------------------------------ Rich
def env_table(tools: dict[str, ToolStatus]) -> Table:
    t = Table(title="Comprobación de entorno", title_style="bold", title_justify="left")
    t.add_column("Herramienta")
    t.add_column("Estado")
    t.add_column("Ubicación", overflow="fold")
    for name, st in tools.items():
        if st.found:
            t.add_row(name, "[green]OK[/]", f"{st.path} [dim]({st.origin})[/]")
        else:
            t.add_row(name, "[red]NO ENCONTRADA[/]", "—")
    return t


def findings_table(title: str, findings: list[Finding]) -> Table:
    t = Table(title=title, title_style="bold", title_justify="left", expand=True)
    t.add_column("Estado", no_wrap=True)
    t.add_column("Nombre", overflow="fold", max_width=28)
    t.add_column("Ruta", overflow="fold", ratio=3)
    t.add_column("Editor / Firma", overflow="fold", ratio=2)
    t.add_column("SHA-256", no_wrap=True)
    t.add_column("VT", no_wrap=True, justify="right")
    t.add_column("Red", no_wrap=True, justify="right")
    for f in sort_findings(findings):
        st = f.status
        t.add_row(
            f"[{st.style}]{st.value}[/]",
            f.name,
            f.path or "—",
            f"{f.publisher}\n[dim]{f.signature}[/]",
            f"{f.sha256[:16]}…" if f.sha256 else "[dim]n/d[/]",
            f"[{st.style}]{f.vt_summary}[/]",
            f"[magenta]{len(f.connections)}[/]" if f.connections else "[dim]—[/]",
        )
    return t


def unique_connections(findings: list[Finding]) -> list[tuple[Connection, Status]]:
    """Una entrada por conexión; si varios hallazgos comparten proceso, gana el peor veredicto."""
    worst: dict[tuple[str, ...], tuple[Connection, Status]] = {}
    for f in findings:
        for c in f.connections:
            key = (c.protocol, c.pid, c.local, c.remote)
            if key not in worst or f.status.rank < worst[key][1].rank:
                worst[key] = (c, f.status)
    return sorted(worst.values(), key=lambda x: (x[1].rank, x[0].process, x[0].remote))


def connections_table(findings: list[Finding]) -> Table:
    t = Table(title="Conexiones activas de procesos señalados", title_style="bold", title_justify="left")
    for col in ("Proceso", "PID", "Proto", "Estado", "Local", "Remoto", "Veredicto"):
        t.add_column(col, overflow="fold")
    for c, st in unique_connections(findings):
        t.add_row(c.process, c.pid, c.protocol, c.state, c.local, c.remote, f"[{st.style}]{st.value}[/]")
    return t


# ------------------------------------------------------------------ Markdown
def _md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _code(s: str) -> str:
    s = (s or "—").replace("|", "\\|").replace("\n", " ")
    return f"`` {s} ``" if "`" in s else f"`{s}`"


def render_markdown(r: TriageResult) -> str:
    counts = r.counts()
    L: list[str] = [f"# Informe win11-triage — {_md(r.host)}", ""]
    if r.dry_run:
        L += ["> [!NOTE]", "> **DRY-RUN**: datos de ejemplo; no se ejecutaron herramientas ni se usó la red.", ""]
    if counts[Status.DETECTED]:
        L += ["> [!CAUTION]", f"> {counts[Status.DETECTED]} elemento(s) detectados por motores de VirusTotal.", ""]

    L += [
        "| Campo | Valor |",
        "|---|---|",
        f"| Fecha | {r.started:%Y-%m-%d %H:%M:%S} |",
        f"| Equipo / usuario | {_md(r.host)} / {_md(r.user)} |",
        f"| Privilegios de administrador | {'sí' if r.admin else 'no'} |",
        f"| Módulos | {', '.join(r.modules) or 'ninguno'} |",
        f"| Ignorados por lista blanca | {r.whitelisted} |",
    ]
    if r.vt_stats:
        s = r.vt_stats
        L.append(
            f"| VirusTotal | {s['network']} consultas nuevas · {s['cache']} desde caché · "
            f"{s['errors']} errores · {s['skipped']} omitidas |"
        )
    L.append(f"| Versión | win11-triage {__version__} |")
    L.append("")

    L += ["## Resumen", "", "| Estado | Total |", "|---|---|"]
    L += [f"| {st.icon} {st.value} | {counts[st]} |" for st in Status]
    L.append("")

    if r.errors:
        L += ["## Errores durante la ejecución", ""] + [f"- {_md(e)}" for e in r.errors] + [""]

    L += ["## Entorno", "", "| Herramienta | Estado | Ruta |", "|---|---|---|"]
    L += [f"| {n} | {'OK' if t.found else 'NO ENCONTRADA'} | {_code(str(t.path or '—'))} |" for n, t in r.tools.items()]
    L.append("")

    for title, findings in r.sections.items():
        L += [f"## {title} ({len(findings)})", ""]
        if not findings:
            L += ["_Sin hallazgos._", ""]
            continue
        L += ["| Estado | Nombre | Ruta | Editor | Firma | VT | Red |", "|---|---|---|---|---|---|---|"]
        for f in sort_findings(findings):
            L.append(
                f"| {f.status.icon} {f.status.value} | {_md(f.name)} | {_code(f.path)} | {_md(f.publisher)} "
                f"| {_md(f.signature)} | {_md(f.vt_summary)} | {len(f.connections) or '—'} |"
            )
        L += ["", "<details><summary>Detalle de cada elemento</summary>", ""]
        for f in sort_findings(findings):
            L += [f"### {f.status.icon} {_md(f.name)}", "", f"- **Ruta:** {_code(f.path)}"]
            if f.location:
                L.append(f"- **Ubicación:** {_code(f.location)}")
            if f.category:
                L.append(f"- **Categoría:** {_md(f.category)}")
            L += [
                f"- **Editor:** {_md(f.publisher)}",
                f"- **Firma:** {_md(f.signature)}",
                f"- **SHA-256:** {_code(f.sha256 or 'n/d')}",
            ]
            v = f.vt or {}
            if v.get("found"):
                label = f" — etiqueta {_code(v['label'])}" if v.get("label") else ""
                L.append(
                    f"- **VirusTotal:** {v.get('malicious', 0)} maliciosos, {v.get('suspicious', 0)} "
                    f"sospechosos de {v.get('total', 0)} motores{label}"
                )
                if v.get("link"):
                    L.append(f"- **Informe VT:** {v['link']}")
            elif v:
                L.append(f"- **VirusTotal:** {_md(f.vt_summary)}")
            for c in f.connections:
                L.append(f"- **Conexión:** {c.protocol} {_code(c.local)} → {_code(c.remote)} ({c.state}, PID {c.pid})")
            L.append("")
        L += ["</details>", ""]

    L += [
        "---",
        "",
        "_Leyenda: 🔴 detectado por VirusTotal · 🟡 sin firma / desconocido · 🟢 limpio o firma válida de terceros._",
        "",
    ]
    return "\n".join(L)


# ------------------------------------------------------------------ JSON
def to_json(r: TriageResult) -> dict[str, Any]:
    return {
        "tool": "win11-triage",
        "version": __version__,
        "host": r.host,
        "user": r.user,
        "started": r.started.isoformat(timespec="seconds"),
        "dry_run": r.dry_run,
        "admin": r.admin,
        "modules": r.modules,
        "tools": {n: (str(t.path) if t.path else None) for n, t in r.tools.items()},
        "summary": {st.value: n for st, n in r.counts().items()},
        "whitelisted": r.whitelisted,
        "vt_stats": r.vt_stats,
        "errors": r.errors,
        "findings": [f.to_dict() for f in sort_findings(r.findings)],
    }


def write_reports(r: TriageResult, out_dir: Path, fmt: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if fmt in ("md", "both"):
        p = out_dir / f"{r.file_stem}.md"
        p.write_text(render_markdown(r), encoding="utf-8")
        written.append(p)
    if fmt in ("json", "both"):
        p = out_dir / f"{r.file_stem}.json"
        p.write_text(json.dumps(to_json(r), indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(p)
    return written
