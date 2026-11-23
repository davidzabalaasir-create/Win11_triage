"""Motor de reglas: convierte hallazgos en señales puntuadas y explicables."""

from __future__ import annotations

from collections.abc import Iterable

from ..models import Finding
from .heuristics import BASE_RULES, Rule, vt_verdict


def apply_rules(findings: Iterable[Finding], rules: list[Rule] | None = None) -> None:
    for f in findings:
        if f.source == "browser":  # señales propias, calculadas al recolectar
            continue
        for rule in rules or BASE_RULES:
            f.signals.extend(rule(f))


def apply_vt(findings: Iterable[Finding]) -> None:
    for f in findings:
        f.signals = [s for s in f.signals if not s.id.startswith("VT_")]
        f.signals.extend(vt_verdict(f))


__all__ = ["apply_rules", "apply_vt"]
