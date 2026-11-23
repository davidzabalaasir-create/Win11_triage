"""Interfaz gráfica de escritorio (CustomTkinter).

Arranque: ``win11-triage-gui``, ``win11-triage --gui`` o ``python -m win11_triage.gui``.

``--selftest`` abre la ventana oculta, ejecuta un análisis de demostración y sale con código 0
si todo funcionó. Lo usa la CI para comprobar que la aplicación instalada arranca de verdad.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from ..engine import default_config_dir

__all__ = ["main"]

log = logging.getLogger("win11_triage")


def _windows_app_id() -> None:
    """Icono propio en la barra de tareas (si no, Windows agrupa la ventana con python.exe)."""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("win11triage.gui")  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass


def _setup_logging(config_dir: Path) -> Path:
    """Registro en <config-dir>/logs/win11-triage.log: imprescindible en el .exe sin consola."""
    logs = config_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / "win11-triage.log"
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return path


def _fatal(log_path: Path | None, exc: BaseException, interactive: bool = True) -> None:
    """Muestra el error al usuario en lugar de cerrarse sin decir nada."""
    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    log.critical("Error fatal en la interfaz:\n%s", detail)
    msg = f"win11-triage no pudo iniciarse:\n\n{type(exc).__name__}: {exc}"
    if log_path:
        msg += f"\n\nDetalles en:\n{log_path}"
    if not interactive:  # autodiagnóstico: nunca bloquear con un diálogo
        if sys.stderr:
            sys.stderr.write(msg + "\n")
        return
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("win11-triage", msg)
        root.destroy()
    except Exception:
        if sys.stderr:
            sys.stderr.write(msg + "\n")


def _selftest(app) -> int:
    """Análisis de demostración con la ventana oculta. 0 = OK."""
    app.withdraw()
    app.var_dry.set(True)
    app.var_format.set("Todos (HTML+MD+JSON+PDF)")
    app.start()
    end = time.monotonic() + 120
    while (app.result is None or (app.worker and app.worker.is_alive())) and time.monotonic() < end:
        app.update()
        time.sleep(0.05)
    ok = app.result is not None and len(app.findings) > 0 and bool(app.reports)
    log.info("Autodiagnóstico %s: %d hallazgos, informes=%s", "OK" if ok else "FALLÓ", len(app.findings), app.reports)
    app.on_close()
    return 0 if ok else 1


def main(config_dir: Path | None = None, argv: list[str] | None = None) -> int:
    selftest = False
    if config_dir is None:
        p = argparse.ArgumentParser(prog="win11-triage-gui", description="Interfaz gráfica de win11-triage.")
        p.add_argument("--config-dir", type=Path, help="carpeta con .env, whitelist.json y vt_cache.json")
        p.add_argument("--selftest", action="store_true", help="análisis de demostración oculto; sale con 0 si va bien")
        args = p.parse_args(argv)
        config_dir, selftest = args.config_dir, args.selftest
    config_dir = (config_dir or default_config_dir()).resolve()

    log_path: Path | None = None
    try:
        log_path = _setup_logging(config_dir)
        log.info("Iniciando interfaz (config: %s, frozen=%s)", config_dir, getattr(sys, "frozen", False))
        import customtkinter as ctk

        from .app import TriageApp

        _windows_app_id()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        app = TriageApp(config_dir)

        def report_callback_exception(exc_type, exc, tb):
            detail = "".join(traceback.format_exception(exc_type, exc, tb))
            log.error("Error en la interfaz:\n%s", detail)
            from tkinter import messagebox

            messagebox.showerror(
                "Error inesperado",
                f"{exc_type.__name__}: {exc}\n\nLa aplicación sigue abierta. Detalles en:\n{log_path}",
                parent=app,
            )

        app.report_callback_exception = report_callback_exception
        if selftest:
            errors: list[str] = []

            def record(exc_type, exc, tb):
                errors.append("".join(traceback.format_exception(exc_type, exc, tb)))
                log.error("Error en la interfaz (autodiagnóstico):\n%s", errors[-1])

            app.report_callback_exception = record
            code = _selftest(app)
            return code if not errors else 1
        app.mainloop()
        return 0
    except Exception as exc:
        _fatal(log_path, exc, interactive=not selftest)
        if selftest and log_path:
            (log_path.parent / f"selftest-error-{datetime.now():%Y%m%d%H%M%S}.txt").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
        return 1
