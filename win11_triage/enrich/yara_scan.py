"""Escaneo YARA opcional (pip install "win11-triage[yara]").

Reglas incluidas: ``rules/yara/win11_triage.yar``. Reglas propias: ``<config-dir>/yara/*.yar``.
Cada regla puede declarar en ``meta`` su ``weight`` (peso), ``mitre`` y ``description``.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Signal

try:
    import yara
except ImportError:  # pragma: no cover - extra opcional
    yara = None  # type: ignore[assignment]

BUILTIN_RULES = Path(__file__).resolve().parent.parent / "rules" / "yara" / "win11_triage.yar"
DEFAULT_WEIGHT = 30


def available() -> bool:
    return yara is not None


def match_to_signal(rule: str, meta: dict) -> Signal:
    return Signal(
        id=f"YARA_{rule}",
        title=f"YARA: {meta.get('description', rule)}",
        weight=int(meta.get("weight", DEFAULT_WEIGHT)),
        attack=str(meta.get("mitre", "")),
        evidence=rule,
    )


class YaraScanner:
    def __init__(self, extra_dir: Path | None = None) -> None:
        if yara is None:
            raise RuntimeError("yara-python no está instalado")
        sources = {"builtin": str(BUILTIN_RULES)}
        if extra_dir and extra_dir.is_dir():
            for i, p in enumerate(sorted(extra_dir.glob("*.yar*"))):
                sources[f"user{i}"] = str(p)
        self.rules = yara.compile(filepaths=sources)
        self.count = len(sources)

    def scan(self, path: Path, timeout: int = 30) -> list[Signal]:
        try:
            matches = self.rules.match(str(path), timeout=timeout)
        except yara.Error:
            return []
        return [match_to_signal(m.rule, m.meta) for m in matches]
