"""Salida en terminal (Rich) y exportación a Markdown / JSON."""

from __future__ import annotations

import base64
import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.table import Table

from . import __copyright__, __version__
from .env_check import ToolStatus
from .models import Connection, Finding, Signal, Status
from .rules.attack import attack_url, technique_name


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
    finished: datetime | None = None
    reviews: dict[str, dict[str, Any]] = field(default_factory=dict)  # Finding.key → {state, note}
    processes: list[dict[str, Any]] = field(default_factory=list)  # snapshot: pid, ppid, name, exe, cmdline, flagged

    def review_of(self, f: Finding) -> dict[str, Any] | None:
        rv = self.reviews.get(f.key)
        return rv if rv and (rv.get("note") or rv.get("state") not in (None, "Pendiente")) else None

    @property
    def findings(self) -> list[Finding]:
        return [f for fs in self.sections.values() for f in fs]

    def counts(self) -> dict[Status, int]:
        c = dict.fromkeys(Status, 0)
        for f in self.findings:
            c[f.status] += 1
        return c

    @property
    def duration(self) -> float | None:
        return (self.finished - self.started).total_seconds() if self.finished else None

    @property
    def file_stem(self) -> str:
        suffix = "_dryrun" if self.dry_run else ""
        return f"triage_{self.host}_{self.started:%Y%m%d_%H%M%S}{suffix}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.status.rank, -f.score, -f.raw_score, f.source, f.name.lower()))


def top_findings(findings: list[Finding], n: int = 5) -> list[Finding]:
    """Lo primero que debería mirar un analista: lo rojo/amarillo con más puntuación."""
    ranked = sorted(
        (f for f in findings if f.status is not Status.CLEAN),
        key=lambda f: (f.status.rank, -f.score, -f.raw_score, f.name.lower()),
    )
    return ranked[:n]


def attack_summary(findings: list[Finding]) -> list[tuple[str, str, int]]:
    """(técnica, nombre, nº de elementos no limpios) ordenado por frecuencia."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.status is Status.CLEAN:
            continue
        for t in f.attack:
            counts[t] = counts.get(t, 0) + 1
    return sorted(((t, technique_name(t), n) for t, n in counts.items()), key=lambda x: (-x[2], x[0]))


def why(f: Finding, n: int = 2) -> str:
    """Resumen corto de las señales positivas de mayor peso."""
    return " · ".join([s.title for s in f.unique_signals if s.weight > 0][:n])


def timeline(findings: list[Finding], limit: int = 40) -> list[Finding]:
    """Elementos con fecha (creación del fichero, arranque del proceso o fecha del evento), del más reciente al más antiguo."""
    dated = [f for f in findings if f.created]
    return sorted(dated, key=lambda f: f.created, reverse=True)[:limit]


def process_chains(r: TriageResult) -> list[list[dict[str, Any]]]:
    """Para cada proceso señalado, su cadena de antecesores: [raíz, …, padre, proceso]."""
    by_pid = {p["pid"]: p for p in r.processes}
    chains = []
    for p in r.processes:
        if not p.get("flagged"):
            continue
        chain, seen, cur = [p], {p["pid"]}, p
        while cur.get("ppid") in by_pid and cur["ppid"] not in seen:
            cur = by_pid[cur["ppid"]]
            seen.add(cur["pid"])
            chain.append(cur)
        chains.append(list(reversed(chain)))
    return sorted(chains, key=lambda ch: -ch[-1].get("score", 0))


@dataclass
class Diff:
    new: list[Finding]
    resolved: list[Finding]
    worse: list[tuple[Finding, int]]  # (actual, puntuación anterior)
    better: list[tuple[Finding, int]]


def diff_results(previous: TriageResult, current: TriageResult, threshold: int = 10) -> Diff:
    """Qué ha cambiado entre dos análisis (por Finding.key)."""
    prev = {f.key: f for f in previous.findings}
    cur = {f.key: f for f in current.findings}
    worse, better = [], []
    for k in cur.keys() & prev.keys():
        delta = cur[k].score - prev[k].score
        if delta >= threshold:
            worse.append((cur[k], prev[k].score))
        elif delta <= -threshold:
            better.append((cur[k], prev[k].score))
    return Diff(
        new=sort_findings([cur[k] for k in cur.keys() - prev.keys()]),
        resolved=sort_findings([prev[k] for k in prev.keys() - cur.keys()]),
        worse=sorted(worse, key=lambda x: -x[0].score),
        better=sorted(better, key=lambda x: -x[0].score),
    )


CSV_COLUMNS = ["estado", "score", "origen", "nombre", "ruta", "linea_comandos", "editor", "firma", "sha256", "vt",
               "conexiones", "att&ck", "por_que", "revision", "nota", "nuevo"]  # fmt: skip


def write_csv(path: Path, findings: list[Finding], reviews: dict[str, dict[str, Any]] | None = None,
              new_keys: set[str] | None = None) -> Path:  # fmt: skip
    """CSV con «;» y BOM UTF-8: Excel en español lo abre directamente."""
    import csv

    reviews, new_keys = reviews or {}, new_keys or set()
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(CSV_COLUMNS)
        for f in findings:
            rv = reviews.get(f.key, {})
            w.writerow([
                f.status.value, f.score, f.source, f.name, f.path, f.cmdline, f.publisher, f.signature, f.sha256,
                f.vt_summary, " | ".join(c.remote for c in f.connections), " ".join(f.attack),
                " | ".join(s.title for s in f.unique_signals if s.weight > 0),
                rv.get("state", "Pendiente"), rv.get("note", ""), "sí" if f.key in new_keys else "",
            ])  # fmt: skip
    return path


def write_evidence_zip(r: TriageResult, path: Path, new_keys: set[str] | None = None) -> Path:
    """Paquete para adjuntar a un ticket: informes, CSV, JSON, revisiones y SHA-256 de todo.

    No incluye los ficheros sospechosos en sí (no se redistribuye malware).
    """
    import hashlib
    import tempfile
    import zipfile

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        files = write_reports(r, tmpdir, "all")
        files.append(write_csv(tmpdir / f"{r.file_stem}.csv", sort_findings(r.findings), r.reviews, new_keys))
        hashes = sorted({(f.sha256, f.name, f.path) for f in r.findings if f.sha256})
        iocs = tmpdir / "iocs_sha256.txt"
        iocs.write_text("".join(f"{h}  {name}  {p}\n" for h, name, p in hashes), encoding="utf-8")
        files.append(iocs)
        readme = tmpdir / "LEEME.txt"
        readme.write_text(
            f"Paquete de evidencias de win11-triage {__version__}\n"
            f"Equipo: {r.host}  Usuario: {r.user}  Fecha: {r.started:%Y-%m-%d %H:%M:%S}\n"
            f"Modo demostración: {'sí' if r.dry_run else 'no'}\n\n"
            "Contenido: informe HTML/Markdown/JSON, CSV para Excel, SHA-256 de los elementos (iocs_sha256.txt)\n"
            "y SHA256SUMS.txt para verificar la integridad de este paquete.\n"
            "No incluye los ficheros sospechosos.\n",
            encoding="utf-8",
        )
        files.append(readme)
        sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files)
        (tmpdir / "SHA256SUMS.txt").write_text(sums, encoding="utf-8")
        files.append(tmpdir / "SHA256SUMS.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in files:
                zf.write(p, arcname=p.name)
    return path


SOURCE_LABEL = {"autoruns": "Persistencia", "sigcheck": "Carpeta usuario", "process": "Proceso", "event": "Evento"}


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
    t.add_column("Score", no_wrap=True, justify="right")
    t.add_column("Nombre", overflow="fold", max_width=30)
    t.add_column("Ruta", overflow="fold", ratio=3)
    t.add_column("Por qué", overflow="fold", ratio=4)
    t.add_column("VT", no_wrap=True, justify="right")
    t.add_column("Red", no_wrap=True, justify="right")
    for f in sort_findings(findings):
        st = f.status
        t.add_row(
            f"[{st.style}]{st.value}[/]",
            f"[{st.style}]{f.score}[/]",
            f.name,
            f.path or "—",
            why(f) or f"[dim]{f.signature}[/]",
            f"[{st.style}]{f.vt_summary}[/]",
            f"[magenta]{len(f.connections)}[/]" if f.connections else "[dim]—[/]",
        )
    return t


def priority_table(findings: list[Finding]) -> Table:
    t = Table(title="Prioriza esto primero", title_style="bold", title_justify="left", expand=True)
    for col, kw in (
        ("#", {"justify": "right"}),
        ("Score", {"justify": "right"}),
        ("Origen", {}),
        ("Nombre", {"overflow": "fold"}),
        ("Por qué", {"overflow": "fold", "ratio": 3}),
        ("ATT&CK", {"overflow": "fold"}),
    ):
        t.add_column(col, **kw)
    for i, f in enumerate(top_findings(findings), 1):
        st = f.status
        t.add_row(
            str(i),
            f"[{st.style}]{f.score}[/]",
            SOURCE_LABEL.get(f.source, f.source),
            f.name,
            why(f, 3),
            ", ".join(f.attack[:4]),
        )
    return t


def attack_table(findings: list[Finding]) -> Table:
    t = Table(title="Técnicas MITRE ATT&CK observadas", title_style="bold", title_justify="left")
    t.add_column("Técnica")
    t.add_column("Nombre")
    t.add_column("Elementos", justify="right")
    for tid, name, n in attack_summary(findings):
        t.add_row(tid, name, str(n))
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

    top = top_findings(r.findings)
    if top:
        L += ["## Prioriza esto primero", "", "| # | Score | Origen | Nombre | Por qué |", "|---|---|---|---|---|"]
        L += [
            f"| {i} | {f.status.icon} {f.score} | {SOURCE_LABEL.get(f.source, f.source)} | {_md(f.name)} | {_md(why(f, 3))} |"
            for i, f in enumerate(top, 1)
        ]
        L.append("")
    techniques = attack_summary(r.findings)
    if techniques:
        L += ["## Técnicas MITRE ATT&CK observadas", "", "| Técnica | Nombre | Elementos |", "|---|---|---|"]
        L += [f"| [{t}]({attack_url(t)}) | {_md(name)} | {n} |" for t, name, n in techniques]
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
        L += ["| Estado | Score | Nombre | Ruta | Por qué | VT | Red |", "|---|---|---|---|---|---|---|"]
        for f in sort_findings(findings):
            L.append(
                f"| {f.status.icon} {f.status.value} | {f.score} | {_md(f.name)} | {_code(f.path)} "
                f"| {_md(why(f)) or '—'} | {_md(f.vt_summary)} | {len(f.connections) or '—'} |"
            )
        L += ["", "<details><summary>Detalle de cada elemento</summary>", ""]
        for f in sort_findings(findings):
            L += [f"### {f.status.icon} {_md(f.name)} — score {f.score}", "", f"- **Ruta:** {_code(f.path)}"]
            if f.cmdline:
                L.append(f"- **Línea de comandos:** {_code(f.cmdline[:400])}")
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
            rv = r.review_of(f)
            if rv:
                note = f" — {_md(rv['note'])}" if rv.get("note") else ""
                L.append(f"- **Revisión del analista:** {_md(rv.get('state', 'Pendiente'))}{note}")
            if f.unique_signals:
                L += ["", "| Señal | Peso | ATT&CK | Evidencia |", "|---|---|---|---|"]
                L += [
                    f"| {_md(x.title)} | {x.weight:+d} | {_md(x.attack) or '—'} | {_code(x.evidence[:160]) if x.evidence else '—'} |"
                    for x in f.unique_signals
                ]
            L.append("")
        L += ["</details>", ""]

    chains = process_chains(r)
    if chains:
        L += ["## Cadenas de procesos sospechosos", ""]
        for ch in chains[:15]:
            L.append(
                "- "
                + " → ".join(
                    (
                        f"**{_md(p['name'])}** ({p['pid']}, score {p.get('score', 0)})"
                        if p.get("flagged")
                        else f"{_md(p['name'])} ({p['pid']})"
                    )
                    for p in ch
                )
            )
        L.append("")

    events = timeline(r.findings)
    if events:
        L += ["## Cronología", "", "| Fecha | Estado | Origen | Nombre |", "|---|---|---|---|"]
        L += [
            f"| {_md(f.created.replace('T', ' '))} | {f.status.icon} {f.score} | {SOURCE_LABEL.get(f.source, f.source)} | {_md(f.name)} |"
            for f in events
        ]
        L.append("")

    L += [
        "---",
        "",
        "_Leyenda: 🔴 VirusTotal ≥ 1 motor o score ≥ 70 · 🟡 score 30–69 o sin firma · "
        "🟢 score < 30 con firma válida o VirusTotal limpio. Herramienta de triaje: no sustituye a un antivirus._",
        "",
        f"_win11-triage {__version__} · {__copyright__} · Licencia MIT_",
        "",
    ]
    return "\n".join(L)


# ------------------------------------------------------------------ JSON
SCHEMA_VERSION = 2


def to_json(r: TriageResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "win11-triage",
        "version": __version__,
        "host": r.host,
        "user": r.user,
        "started": r.started.isoformat(timespec="seconds"),
        "finished": r.finished.isoformat(timespec="seconds") if r.finished else None,
        "dry_run": r.dry_run,
        "admin": r.admin,
        "modules": r.modules,
        "tools": {n: (str(t.path) if t.path else None) for n, t in r.tools.items()},
        "summary": {st.value: n for st, n in r.counts().items()},
        "max_score": max((f.score for f in r.findings), default=0),
        "attack": [{"id": t, "name": name, "count": n} for t, name, n in attack_summary(r.findings)],
        "priority": [f"{f.source}:{f.name}" for f in top_findings(r.findings)],
        "whitelisted": r.whitelisted,
        "vt_stats": r.vt_stats,
        "errors": r.errors,
        "sections": {title: [f.to_dict() for f in sort_findings(fs)] for title, fs in r.sections.items()},
        "findings": [_with_review(r, f) for f in sort_findings(r.findings)],
        "process_tree": r.processes,
    }


def _with_review(r: TriageResult, f: Finding) -> dict[str, Any]:
    d = f.to_dict()
    d["key"] = f.key
    rv = r.review_of(f)
    if rv:
        d["review"] = {"state": rv.get("state"), "note": rv.get("note", ""), "updated": rv.get("updated")}
    return d


def _finding_from_dict(d: dict[str, Any]) -> Finding:
    skip = {"connections", "signals", "key", "review"}
    fields = {k: d.get(k) for k in Finding.__dataclass_fields__ if k in d and k not in skip}
    f = Finding(**fields)
    f.connections = [Connection(**c) for c in d.get("connections") or []]
    f.signals = [Signal(**x) for x in d.get("signals") or []]
    return f


def load_json(path: Path) -> TriageResult:
    """Reconstruye un TriageResult a partir de un informe JSON (para el historial)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    tools = {n: ToolStatus(n, Path(p) if p else None, "informe") for n, p in (data.get("tools") or {}).items()}
    finished = data.get("finished")
    r = TriageResult(
        host=data.get("host", "?"),
        user=data.get("user", "?"),
        started=datetime.fromisoformat(data["started"]),
        dry_run=bool(data.get("dry_run")),
        admin=bool(data.get("admin")),
        tools=tools,
        modules=list(data.get("modules") or []),
        whitelisted=int(data.get("whitelisted") or 0),
        vt_stats=data.get("vt_stats"),
        errors=list(data.get("errors") or []),
        finished=datetime.fromisoformat(finished) if finished else None,
        processes=list(data.get("process_tree") or []),
    )
    sections = data.get("sections")
    if sections is None:  # informes de la v1.1: solo lista plana
        sections = {}
        for d in data.get("findings", []):
            sections.setdefault(d.get("source", "hallazgos"), []).append(d)
    r.sections = {title: [_finding_from_dict(d) for d in items] for title, items in sections.items()}
    return r


# ------------------------------------------------------------------ HTML
_ASSETS = Path(__file__).resolve().parent / "assets"
_HTML_COLOR = {Status.DETECTED: "#ef4444", Status.UNKNOWN: "#eab308", Status.CLEAN: "#22c55e"}
_CSS = """
:root{--bg:#0f172a;--panel:#111827;--card:#1f2937;--border:#374151;--text:#e5e7eb;--muted:#9ca3af}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:auto;padding:32px}header{display:flex;align-items:center;gap:16px;margin-bottom:8px}
header img{width:56px;height:56px}h1{margin:0;font-size:26px}h2{margin:36px 0 12px;font-size:19px}
.muted{color:var(--muted)}.note{background:#1e293b;border-left:4px solid #38bdf8;padding:10px 14px;border-radius:6px;margin:16px 0}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;border-top:4px solid var(--c)}
.card b{display:block;font-size:32px;color:var(--c)}table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}th{background:var(--panel);color:var(--muted);font-weight:600}
td code{font:12px Consolas,monospace;color:#cbd5e1;word-break:break-all}.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:12px;color:#0f172a;background:var(--c)}
details{background:var(--card);border:1px solid var(--border);border-radius:10px;margin:8px 0;padding:10px 14px}summary{cursor:pointer;font-weight:600}
dl{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;margin:10px 0 0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
a{color:#38bdf8}footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{body{background:#fff;color:#111}.card,table,details{background:#fff}th{background:#eee}}
"""


def _e(s: Any) -> str:
    return html.escape(str(s if s not in (None, "") else "—"))


def _logo_data_uri() -> str:
    try:
        return "data:image/png;base64," + base64.b64encode((_ASSETS / "icon_64.png").read_bytes()).decode()
    except OSError:
        return ""


def render_html(r: TriageResult) -> str:
    """Informe autocontenido (sin recursos externos), imprimible a PDF desde el navegador."""
    c = r.counts()
    cards = "".join(
        f'<div class="card" style="--c:{color}"><b>{n}</b>{label}</div>'
        for color, n, label in (
            (_HTML_COLOR[Status.DETECTED], c[Status.DETECTED], "Detectados"),
            (_HTML_COLOR[Status.UNKNOWN], c[Status.UNKNOWN], "Sin firma / desconocidos"),
            (_HTML_COLOR[Status.CLEAN], c[Status.CLEAN], "Limpios"),
            ("#9ca3af", r.whitelisted, "En lista blanca"),
        )
    )
    meta = [
        ("Fecha", f"{r.started:%Y-%m-%d %H:%M:%S}"),
        ("Equipo / usuario", f"{r.host} / {r.user}"),
        ("Administrador", "sí" if r.admin else "no"),
        ("Módulos", ", ".join(r.modules) or "ninguno"),
    ]
    if r.duration is not None:
        meta.append(("Duración", f"{r.duration:.0f} s"))
    if r.vt_stats:
        s = r.vt_stats
        meta.append(
            (
                "VirusTotal",
                f"{s['network']} nuevas · {s['cache']} caché · {s['errors']} errores · {s['skipped']} omitidas",
            )
        )
    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>win11-triage — {_e(r.host)}</title><style>{_CSS}</style></head><body><main>",
        f"<header><img src='{_logo_data_uri()}' alt=''><div><h1>Informe de triaje — {_e(r.host)}</h1>",
        f"<div class='muted'>win11-triage {__version__} · {r.started:%d/%m/%Y %H:%M}</div></div></header>",
    ]
    if r.dry_run:
        parts.append("<div class='note'><b>Modo demostración:</b> datos de ejemplo, sin herramientas ni red.</div>")
    parts.append(f"<div class='cards'>{cards}</div>")
    parts.append("<table>" + "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in meta) + "</table>")
    if r.errors:
        parts.append("<h2>Errores y avisos</h2><ul>" + "".join(f"<li>{_e(e)}</li>" for e in r.errors) + "</ul>")

    top = top_findings(r.findings)
    if top:
        rows = "".join(
            f"<tr><td>{i}</td><td><span class='badge' style='--c:{_HTML_COLOR[f.status]}'>{f.score}</span></td>"
            f"<td>{_e(SOURCE_LABEL.get(f.source, f.source))}</td><td>{_e(f.name)}</td><td>{_e(why(f, 3))}</td></tr>"
            for i, f in enumerate(top, 1)
        )
        parts.append(
            "<h2>Prioriza esto primero</h2><table><tr><th>#</th><th>Score</th><th>Origen</th><th>Nombre</th>"
            f"<th>Por qué</th></tr>{rows}</table>"
        )
    techniques = attack_summary(r.findings)
    if techniques:
        rows = "".join(
            f"<tr><td><a href='{attack_url(t)}'>{_e(t)}</a></td><td>{_e(name)}</td><td>{n}</td></tr>"
            for t, name, n in techniques
        )
        parts.append(
            f"<h2>Técnicas MITRE ATT&amp;CK observadas</h2><table><tr><th>Técnica</th><th>Nombre</th>"
            f"<th>Elementos</th></tr>{rows}</table>"
        )

    for title, findings in r.sections.items():
        parts.append(f"<h2>{_e(title)} ({len(findings)})</h2>")
        if not findings:
            parts.append("<p class='muted'>Sin hallazgos.</p>")
            continue
        rows = "".join(
            f"<tr><td><span class='badge' style='--c:{_HTML_COLOR[f.status]}'>{f.status.value}</span></td>"
            f"<td><b>{f.score}</b></td><td>{_e(f.name)}</td><td><code>{_e(f.path)}</code></td>"
            f"<td>{_e(why(f) or f.signature)}</td><td>{_e(f.vt_summary)}</td>"
            f"<td>{len(f.connections) or '—'}</td></tr>"
            for f in sort_findings(findings)
        )
        parts.append(
            "<table><tr><th>Estado</th><th>Score</th><th>Nombre</th><th>Ruta</th><th>Por qué</th><th>VT</th>"
            f"<th>Red</th></tr>{rows}</table>"
        )
        for f in sort_findings(findings):
            vt = f.vt or {}
            items = [
                ("Ruta", f"<code>{_e(f.path)}</code>"),
                ("Línea de comandos", f"<code>{_e(f.cmdline[:400])}</code>"),
                ("Ubicación", f"<code>{_e(f.location)}</code>"),
                ("Categoría", _e(f.category)),
                ("Editor", _e(f.publisher)),
                ("Firma", _e(f.signature)),
                ("SHA-256", f"<code>{_e(f.sha256)}</code>"),
                ("VirusTotal", _e(f.vt_summary) + (f" — {_e(vt['label'])}" if vt.get("label") else "")),
            ]
            if vt.get("link"):
                items.append(("Informe VT", f"<a href='{_e(vt['link'])}'>{_e(vt['link'])}</a>"))
            items += [
                ("Conexión", f"<code>{_e(x.local)} → {_e(x.remote)}</code> ({_e(x.state)}, PID {_e(x.pid)})")
                for x in f.connections
            ]
            rv = r.review_of(f)
            if rv:
                items.append(
                    ("Revisión", f"<b>{_e(rv.get('state'))}</b>" + (f" — {_e(rv['note'])}" if rv.get("note") else ""))
                )
            dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in items)
            sig_rows = "".join(
                f"<tr><td>{_e(x.title)}</td><td>{x.weight:+d}</td><td>{_e(x.attack)}</td>"
                f"<td><code>{_e(x.evidence[:200])}</code></td></tr>"
                for x in f.unique_signals
            )
            sig_table = (
                f"<table><tr><th>Señal</th><th>Peso</th><th>ATT&amp;CK</th><th>Evidencia</th></tr>{sig_rows}</table>"
                if sig_rows
                else ""
            )
            parts.append(
                f"<details><summary><span class='badge' style='--c:{_HTML_COLOR[f.status]}'>{f.status.value}</span> "
                f"{_e(f.name)} <span class='muted'>· score {f.score}</span></summary><dl>{dl}</dl>{sig_table}</details>"
            )

    chains = process_chains(r)
    if chains:
        items = "".join(
            "<li>"
            + " → ".join(
                (
                    f"<b style='color:{_HTML_COLOR[Status.DETECTED] if p.get('score', 0) >= 70 else _HTML_COLOR[Status.UNKNOWN]}'>"
                    f"{_e(p['name'])}</b> <span class='muted'>({p['pid']})</span>"
                )
                if p.get("flagged")
                else f"{_e(p['name'])} <span class='muted'>({p['pid']})</span>"
                for p in ch
            )
            + "</li>"
            for ch in chains[:15]
        )
        parts.append(f"<h2>Cadenas de procesos sospechosos</h2><ul class='chains'>{items}</ul>")

    events = timeline(r.findings)
    if events:
        rows = "".join(
            f"<tr><td><code>{_e(f.created.replace('T', ' '))}</code></td>"
            f"<td><span class='badge' style='--c:{_HTML_COLOR[f.status]}'>{f.score}</span></td>"
            f"<td>{_e(SOURCE_LABEL.get(f.source, f.source))}</td><td>{_e(f.name)}</td></tr>"
            for f in events
        )
        parts.append(
            "<h2>Cronología</h2><table><tr><th>Fecha</th><th>Score</th><th>Origen</th><th>Nombre</th></tr>"
            f"{rows}</table>"
        )

    conns = unique_connections(r.findings)
    if conns:
        rows = "".join(
            f"<tr><td>{_e(x.process)}</td><td>{_e(x.pid)}</td><td>{_e(x.protocol)}</td><td>{_e(x.state)}</td>"
            f"<td><code>{_e(x.local)}</code></td><td><code>{_e(x.remote)}</code></td>"
            f"<td><span class='badge' style='--c:{_HTML_COLOR[st]}'>{st.value}</span></td></tr>"
            for x, st in conns
        )
        parts.append(
            "<h2>Conexiones activas</h2><table><tr><th>Proceso</th><th>PID</th><th>Proto</th><th>Estado</th>"
            f"<th>Local</th><th>Remoto</th><th>Veredicto</th></tr>{rows}</table>"
        )
    parts.append(
        "<footer>🔴 detectado por VirusTotal · 🟡 sin firma / desconocido · 🟢 limpio o firma válida de terceros. "
        f"Herramienta de triaje: no sustituye a un antivirus.<br>win11-triage {__version__} · {__copyright__} · Licencia MIT</footer></main></body></html>"
    )
    return "".join(parts)


FORMAT_CHOICES = ("md", "html", "json", "both", "all")


def write_reports(r: TriageResult, out_dir: Path, fmt: str) -> list[Path]:
    """fmt: md | html | json | both (md+json) | all (md+html+json)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = {"md": {"md"}, "html": {"html"}, "json": {"json"}, "both": {"md", "json"}, "all": {"md", "html", "json"}}[
        fmt
    ]
    renderers = {
        "md": render_markdown,
        "html": render_html,
        "json": lambda res: json.dumps(to_json(res), indent=2, ensure_ascii=False),
    }
    written = []
    for ext in ("md", "html", "json"):
        if ext in wanted:
            p = out_dir / f"{r.file_stem}.{ext}"
            p.write_text(renderers[ext](r), encoding="utf-8")
            written.append(p)
    return written
