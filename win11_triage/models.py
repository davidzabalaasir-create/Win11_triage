"""Modelo de datos común a todos los módulos."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any


class Cancelled(Exception):
    """El usuario canceló el análisis."""


class Status(str, Enum):
    """Veredicto final de un hallazgo. El orden define la prioridad de presentación."""

    DETECTED = "DETECTADO"
    UNKNOWN = "DESCONOCIDO"
    CLEAN = "LIMPIO"

    @property
    def style(self) -> str:
        return {"DETECTADO": "bold red", "DESCONOCIDO": "yellow", "LIMPIO": "green"}[self.value]

    @property
    def icon(self) -> str:
        return {"DETECTADO": "🔴", "DESCONOCIDO": "🟡", "LIMPIO": "🟢"}[self.value]

    @property
    def rank(self) -> int:
        return list(Status).index(self)


# Umbrales de puntuación (decisión D3 del plan de detección avanzada)
SCORE_DETECTED = 70
SCORE_SUSPICIOUS = 30


@dataclass(frozen=True)
class Signal:
    """Una razón concreta, con evidencia, por la que un elemento es sospechoso (o menos)."""

    id: str  # identificador estable, p. ej. "CMD_PS_ENCODED"
    title: str  # texto para el informe
    weight: int  # suma a la puntuación (negativo = resta, p. ej. firma válida)
    attack: str = ""  # técnica MITRE ATT&CK, p. ej. "T1059.001"
    evidence: str = ""  # fragmento que disparó la regla


@dataclass
class Connection:
    """Conexión TCP/UDP (psutil o tcpvcon)."""

    protocol: str
    process: str
    pid: str
    state: str
    local: str
    remote: str


@dataclass
class Finding:
    source: str  # "autoruns" | "sigcheck" | "process" | "event"
    name: str
    path: str
    publisher: str
    signature: str  # texto de firma tal como lo da Sysinternals
    sha256: str
    category: str = ""  # categoría de autoruns / tipo de hallazgo
    location: str = ""  # clave de registro, tarea, carpeta escaneada…
    signed_ok: bool = False  # firma válida de un tercero
    vt: dict[str, Any] | None = None
    connections: list[Connection] = field(default_factory=list)
    cmdline: str = ""  # línea de lanzamiento / línea de comandos
    pid: int | None = None
    ppid: int | None = None
    parent: str = ""  # nombre del proceso padre
    created: str = ""  # ISO 8601: creación del fichero/proceso o fecha del evento
    signals: list[Signal] = field(default_factory=list)

    def add(self, signal: Signal | None) -> None:
        if signal is not None:
            self.signals.append(signal)

    @property
    def unique_signals(self) -> list[Signal]:
        """Una señal por id (la de mayor peso), ordenadas de más a menos relevante."""
        best: dict[str, Signal] = {}
        for sig in self.signals:
            if sig.id not in best or sig.weight > best[sig.id].weight:
                best[sig.id] = sig
        return sorted(best.values(), key=lambda x: -x.weight)

    @property
    def raw_score(self) -> int:
        """Suma sin saturar: desempata elementos con score 100."""
        return sum(s.weight for s in self.unique_signals)

    @property
    def score(self) -> int:
        return max(0, min(100, sum(s.weight for s in self.unique_signals)))

    @property
    def attack(self) -> list[str]:
        return sorted({t.strip() for s in self.unique_signals for t in s.attack.split(",") if t.strip()})

    @property
    def image_name(self) -> str:
        """Nombre del ejecutable (para correlacionar con tcpvcon)."""
        return PureWindowsPath(self.path.strip('"')).name.lower() if self.path else ""

    @property
    def status(self) -> Status:
        """🔴 VT ≥ 1 motor o score ≥ 70 · 🟡 score 30–69 o sin firma · 🟢 resto firmado o VT limpio."""
        vt = self.vt or {}
        vt_found = bool(vt.get("found"))
        if (vt_found and vt.get("malicious", 0) > 0) or self.score >= SCORE_DETECTED:
            return Status.DETECTED
        if self.score >= SCORE_SUSPICIOUS:
            return Status.UNKNOWN
        vt_clean = vt_found and vt.get("malicious", 0) == 0 and vt.get("suspicious", 0) == 0
        return Status.CLEAN if (self.signed_ok or vt_clean) else Status.UNKNOWN

    @property
    def vt_summary(self) -> str:
        if not self.vt:
            return "—"
        if self.vt.get("error"):
            return f"error: {self.vt['error']}"
        if not self.vt.get("found"):
            return "no encontrado"
        return f"{self.vt.get('malicious', 0)}/{self.vt.get('total', 0)}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signals"] = [asdict(x) for x in self.unique_signals]
        data["status"] = self.status.value
        data["score"] = self.score
        data["attack"] = self.attack
        return data
