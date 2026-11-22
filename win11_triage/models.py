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


@dataclass
class Connection:
    """Conexión TCP/UDP reportada por tcpvcon."""

    protocol: str
    process: str
    pid: str
    state: str
    local: str
    remote: str


@dataclass
class Finding:
    source: str  # "autoruns" | "sigcheck"
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

    @property
    def image_name(self) -> str:
        """Nombre del ejecutable (para correlacionar con tcpvcon)."""
        return PureWindowsPath(self.path.strip('"')).name.lower() if self.path else ""

    @property
    def status(self) -> Status:
        vt = self.vt or {}
        if vt.get("found"):
            if vt.get("malicious", 0) > 0:
                return Status.DETECTED
            return Status.CLEAN if vt.get("suspicious", 0) == 0 else Status.UNKNOWN
        # Sin veredicto de VT: una firma válida de un tercero se considera limpia.
        return Status.CLEAN if self.signed_ok else Status.UNKNOWN

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
        data["status"] = self.status.value
        return data
