"""Localización de las herramientas de Sysinternals."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TOOLS = {
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
        "used_by": "(reservado para conexiones de red)",
    },
}


@dataclass
class ToolStatus:
    name: str
    path: Optional[Path]
    origin: str  # PATH | WinGet | SYSINTERNALS_DIR | ""

    @property
    def found(self) -> bool:
        return self.path is not None


def _candidates(name: str) -> list[str]:
    stem = name[:-4]
    return [name, f"{stem}64.exe"]


def _search_dir(base: Path, name: str, recursive: bool) -> Optional[Path]:
    if not base.is_dir():
        return None
    for cand in _candidates(name):
        direct = base / cand
        if direct.is_file():
            return direct
        if recursive:
            hits = sorted(p for p in base.rglob("*") if p.name.lower() == cand.lower())
            if hits:
                return hits[0]
    return None


def find_tool(name: str) -> ToolStatus:
    custom = os.environ.get("SYSINTERNALS_DIR")
    if custom:
        hit = _search_dir(Path(os.path.expandvars(custom)), name, recursive=False)
        if hit:
            return ToolStatus(name, hit, "SYSINTERNALS_DIR")

    for cand in _candidates(name):
        p = shutil.which(cand)
        if p:
            return ToolStatus(name, Path(p), "PATH")

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
        f"  o descarga manual: {info['url']} (añade la carpeta al PATH o define SYSINTERNALS_DIR en .env)"
    )
