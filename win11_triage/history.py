"""Historial de análisis: lee los informes JSON de la carpeta de informes y compara ejecuciones."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import Finding


@dataclass
class HistoryEntry:
    path: Path
    started: datetime
    host: str
    dry_run: bool
    summary: dict[str, int]
    max_score: int
    keys: frozenset[str]

    @property
    def total(self) -> int:
        return sum(self.summary.values())

    def sibling(self, ext: str) -> Path | None:
        p = self.path.with_suffix(ext)
        return p if p.exists() else None


def finding_key(source: str, path: str, sha256: str, name: str = "", rule: str = "") -> str:
    """Identidad estable de un hallazgo entre ejecuciones (igual que ``Finding.key``)."""
    ident = (path or name).strip().strip(chr(34)).lower()
    if source == "sigma":  # varias reglas pueden coincidir en el mismo binario
        ident = f"{(rule or name).lower()}|{ident}"
    return f"{source}|{ident}|{(sha256 or '').lower()}"


def _rule_or_name(x: dict) -> str:
    """Para Sigma, el id de la regla (igual que Finding.key); si no, el nombre."""
    if x.get("source") == "sigma":
        for s in x.get("signals") or []:
            if str(s.get("id", "")).startswith("SIGMA_"):
                return str(s["id"])
    return x.get("name", "")


def key_of(f: Finding) -> str:
    return f.key


def list_reports(folder: Path, limit: int = 200) -> list[HistoryEntry]:
    entries = []
    if not folder.is_dir():
        return entries
    for p in sorted(folder.glob("triage_*.json"), reverse=True)[:limit]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            entries.append(
                HistoryEntry(
                    path=p,
                    started=datetime.fromisoformat(d["started"]),
                    host=d.get("host", "?"),
                    dry_run=bool(d.get("dry_run")),
                    summary=dict(d.get("summary", {})),
                    max_score=int(d.get("max_score", 0)),
                    keys=frozenset(
                        finding_key(
                            x.get("source", ""),
                            x.get("path", ""),
                            x.get("sha256", ""),
                            x.get("name", ""),
                            _rule_or_name(x),
                        )
                        for x in d.get("findings", [])
                    ),
                )
            )
        except (OSError, ValueError, KeyError, TypeError):
            continue  # informe corrupto o de otra herramienta: se ignora
    return sorted(entries, key=lambda e: e.started, reverse=True)


def previous_of(
    entries: list[HistoryEntry], current: Path | None, started: datetime, dry_run: bool
) -> HistoryEntry | None:
    """Último análisis del mismo tipo (real/demostración) anterior al actual."""
    for e in entries:
        if e.path != current and e.dry_run == dry_run and e.started < started:
            return e
    return None
