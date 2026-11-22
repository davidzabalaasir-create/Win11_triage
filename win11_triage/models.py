"""Modelo de datos común para todos los módulos."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

CLEAN = "LIMPIO"
UNKNOWN = "DESCONOCIDO"
DETECTED = "DETECTADO"

STATUS_STYLE = {CLEAN: "green", UNKNOWN: "yellow", DETECTED: "bold red"}


@dataclass
class Finding:
    source: str            # "autoruns" | "sigcheck"
    name: str
    path: str
    publisher: str
    signature: str         # texto de firma tal como lo da Sysinternals
    sha256: str
    category: str = ""     # categoría de autoruns / carpeta escaneada
    location: str = ""     # clave de registro, tarea, etc.
    signed_ok: bool = False  # firma válida de un tercero
    vt: Optional[dict] = field(default=None)

    @property
    def status(self) -> str:
        if self.vt and self.vt.get("found"):
            if self.vt.get("malicious", 0) > 0:
                return DETECTED
            if self.vt.get("suspicious", 0) == 0:
                return CLEAN
            return UNKNOWN
        # Sin datos de VT: una firma válida de terceros se considera limpia.
        return CLEAN if self.signed_ok else UNKNOWN

    @property
    def vt_summary(self) -> str:
        if not self.vt:
            return "—"
        if self.vt.get("error"):
            return f"error: {self.vt['error']}"
        if not self.vt.get("found"):
            return "no encontrado"
        return f"{self.vt.get('malicious', 0)}/{self.vt.get('total', 0)}"
