"""Localización de las herramientas de Sysinternals y comprobaciones del sistema."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .utils import expand_win_vars

TOOLS: dict[str, dict[str, str]] = {
    "autorunsc.exe": {
        "winget": "Microsoft.Sysinternals.Autoruns",
        "url": "https://learn.microsoft.com/sysinternals/downloads/autoruns",
        "used_by": "--autoruns",
    },
    "sigcheck.exe": {
        "winget": "Microsoft.Sysinternals.Sigcheck",
        "url": "https://learn.microsoft.com/sysinternals/downloads/sigcheck",
        "used_by": "--scan-user",
    },
    "tcpvcon.exe": {
        "winget": "Microsoft.Sysinternals.TCPView",
        "url": "https://learn.microsoft.com/sysinternals/downloads/tcpview",
        "used_by": "--network",
    },
}


@dataclass(frozen=True)
class ToolStatus:
    name: str
    path: Path | None
    origin: str  # PATH | WinGet | SYSINTERNALS_DIR | ""

    @property
    def found(self) -> bool:
        return self.path is not None


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_admin() -> bool:
    """True si el proceso corre elevado (Windows) o como root (resto)."""
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _candidates(name: str) -> list[str]:
    """autorunsc.exe → [autorunsc.exe, autorunsc64.exe] (WinGet instala ambas)."""
    stem = name[:-4]
    return [name, f"{stem}64.exe"]


def _search_dir(base: Path, name: str, recursive: bool) -> Path | None:
    if not base.is_dir():
        return None
    wanted = [c.lower() for c in _candidates(name)]
    for cand in _candidates(name):
        if (base / cand).is_file():
            return base / cand
    if recursive:
        hits = sorted(p for p in base.rglob("*.exe") if p.name.lower() in wanted)
        if hits:
            # Preferimos la variante que coincide exactamente con el nombre pedido.
            hits.sort(key=lambda p: wanted.index(p.name.lower()))
            return hits[0]
    return None


def find_tool(name: str) -> ToolStatus:
    custom = os.environ.get("SYSINTERNALS_DIR")
    if custom:
        hit = _search_dir(Path(expand_win_vars(custom)), name, recursive=False)
        if hit:
            return ToolStatus(name, hit, "SYSINTERNALS_DIR")

    for cand in _candidates(name):
        found = shutil.which(cand)
        if found:
            return ToolStatus(name, Path(found), "PATH")

    local = os.environ.get("LOCALAPPDATA")
    if local:
        winget = Path(local) / "Microsoft" / "WinGet"
        hit = _search_dir(winget / "Links", name, recursive=False) or _search_dir(
            winget / "Packages", name, recursive=True
        )
        if hit:
            return ToolStatus(name, hit, "WinGet")

    return ToolStatus(name, None, "")


def check_all() -> dict[str, ToolStatus]:
    return {name: find_tool(name) for name in TOOLS}


def install_hint(name: str) -> str:
    info = TOOLS[name]
    return (
        f"winget install --id {info['winget']} -e --accept-source-agreements\n"
        f"o descarga manual: {info['url']}\n"
        "(añade la carpeta al PATH o define SYSINTERNALS_DIR en .env)"
    )


def relaunch_as_admin(args: list[str]) -> bool:
    """Reabre el programa elevado (UAC). Devuelve True si Windows aceptó lanzarlo."""
    if not is_windows():
        return False
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(args)
    else:
        exe, params = sys.executable, subprocess.list2cmdline(["-m", "win11_triage.gui", *args])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)  # type: ignore[attr-defined]
    return int(rc) > 32
