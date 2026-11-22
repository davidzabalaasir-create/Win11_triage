"""Interfaz gráfica de escritorio (CustomTkinter).

Arranque: ``win11-triage-gui``, ``win11-triage --gui`` o ``python -m win11_triage.gui``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..engine import default_config_dir

__all__ = ["main"]


def _windows_app_id() -> None:
    """Icono propio en la barra de tareas (si no, Windows agrupa la ventana con python.exe)."""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("win11triage.gui")  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass


def main(config_dir: Path | None = None, argv: list[str] | None = None) -> int:
    if config_dir is None:
        p = argparse.ArgumentParser(prog="win11-triage-gui", description="Interfaz gráfica de win11-triage.")
        p.add_argument("--config-dir", type=Path, help="carpeta con .env, whitelist.json y vt_cache.json")
        config_dir = p.parse_args(argv).config_dir
    import customtkinter as ctk

    from .app import TriageApp

    _windows_app_id()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = TriageApp((config_dir or default_config_dir()).resolve())
    app.mainloop()
    return 0
