"""Comprobación manual de nuevas versiones en GitHub Releases (solo cuando el usuario lo pide)."""

from __future__ import annotations

import re
from dataclasses import dataclass

import requests

from . import __version__

REPO = "davidzabalaasir-create/Win11_triage"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{REPO}/releases/latest"


@dataclass
class UpdateInfo:
    current: str
    latest: str
    url: str

    @property
    def available(self) -> bool:
        return parse_version(self.latest) > parse_version(self.current)


def parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def check_latest(timeout: float = 6.0) -> UpdateInfo:
    """Lanza requests.RequestException si no hay conexión."""
    r = requests.get(
        API,
        timeout=timeout,
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"win11-triage/{__version__}"},
    )
    r.raise_for_status()
    data = r.json()
    return UpdateInfo(__version__, str(data.get("tag_name", "")).lstrip("v"), data.get("html_url") or RELEASES_URL)
