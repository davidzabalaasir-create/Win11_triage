"""Análisis programado con el Programador de tareas de Windows (schtasks).

Crea la tarea ``\\win11-triage\\Análisis programado`` que ejecuta un ``scheduled_scan.cmd`` guardado
en la carpeta de configuración (schtasks limita /TR a 261 caracteres). El análisis programado usa
``--alert-new``: solo avisa (notificación, webhook) si hay hallazgos nuevos o que han empeorado.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .collectors import decode_output

TASK_NAME = r"\win11-triage\Analisis programado"
DEFAULT_MODULES = ("--autoruns", "--scan-user", "--processes", "--events", "7", "--sigma", "--browsers", "--network")
FREQUENCIES = {"daily": "DAILY", "weekly": "WEEKLY"}


def cli_command() -> list[str]:
    """Cómo invocar la CLI: el .exe de consola junto a la app instalada, o Python + módulo."""
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        return [str(exe_dir / "win11-triage.exe")]
    return [sys.executable, "-m", "win11_triage"]


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def script_text(config_dir: Path, modules: tuple[str, ...] = DEFAULT_MODULES, extra: tuple[str, ...] = ()) -> str:
    args = [
        *cli_command(),
        *modules,
        "--config-dir",
        str(config_dir),
        "--format",
        "all",
        "--alert-new",
        "--notify",
        "--no-color",
        *extra,
    ]
    log = config_dir / "reportes" / "programado.log"
    return "@echo off\r\nchcp 65001 >nul\r\n" + " ".join(_quote(a) for a in args) + f' >> "{log}" 2>&1\r\n'


def schtasks_create_args(script: Path, frequency: str, at: str, admin: bool) -> list[str]:
    if frequency not in FREQUENCIES:
        raise ValueError(f"Frecuencia no válida: {frequency} (usa daily, weekly u off)")
    hh, _, mm = at.partition(":")
    if not (hh.isdigit() and mm.isdigit() and 0 <= int(hh) < 24 and 0 <= int(mm) < 60):
        raise ValueError(f"Hora no válida: {at} (formato HH:MM)")
    # conhost --headless: la consola no aparece en pantalla mientras corre el análisis
    args = ["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/TR", f'conhost.exe --headless "{script}"']
    args += ["/SC", FREQUENCIES[frequency], "/ST", f"{int(hh):02d}:{int(mm):02d}"]
    if frequency == "weekly":
        args += ["/D", "MON"]
    if admin:
        args += ["/RL", "HIGHEST"]  # autoruns ve todas las ubicaciones con privilegios elevados
    return args


def _run(args: list[str]) -> str:
    proc = subprocess.run(
        args, capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False
    )
    out = decode_output(proc.stdout) + decode_output(proc.stderr)
    if proc.returncode != 0:
        raise RuntimeError(out.strip() or f"schtasks código {proc.returncode}")
    return out.strip()


def create(
    config_dir: Path, frequency: str, at: str = "09:00", admin: bool = False, extra: tuple[str, ...] = ()
) -> Path:
    script = config_dir / "scheduled_scan.cmd"
    (config_dir / "reportes").mkdir(parents=True, exist_ok=True)
    script.write_text(script_text(config_dir, extra=extra), encoding="utf-8")
    _run(schtasks_create_args(script, frequency, at, admin))
    return script


def delete() -> None:
    _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME])


def status() -> str:
    """Texto de schtasks /Query o «no programado»."""
    try:
        return _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
    except (RuntimeError, OSError):
        return "no programado"
