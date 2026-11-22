"""Enriquecedores caros (análisis de contenido): solo se aplican a hallazgos ya señalados."""

from __future__ import annotations

import os
from pathlib import Path

from ..models import Finding
from ..utils import expand_win_vars

MAX_FILE_SIZE = 64 * 1024 * 1024  # no se analizan ficheros mayores (lentitud, instaladores)
SCRIPT_EXT = (".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk")
PE_EXT = (".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx")


def file_of(f: Finding) -> Path | None:
    """Ruta local del fichero del hallazgo si existe y es analizable."""
    raw = (f.path or "").strip().strip('"')
    if not raw or raw.lower().startswith("file not found"):
        return None
    p = Path(expand_win_vars(raw))
    try:
        if p.is_file() and os.path.getsize(p) <= MAX_FILE_SIZE:
            return p
    except OSError:
        return None
    return None


def eligible(f: Finding) -> bool:
    """Solo lo no firmado o con señales positivas merece el coste de analizar su contenido."""
    return not f.signed_ok or f.score > 0
