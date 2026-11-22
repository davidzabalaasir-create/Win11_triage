"""Paleta y recursos visuales de la interfaz (tema oscuro)."""

from __future__ import annotations

from pathlib import Path

from ..models import Status

BG = "#0b1120"
PANEL = "#111827"
CARD = "#1f2937"
CARD_ALT = "#1a2332"
BORDER = "#334155"
TEXT = "#e5e7eb"
MUTED = "#94a3b8"
ACCENT = "#2563eb"
ACCENT_HOVER = "#1d4ed8"
CYAN = "#38bdf8"
PURPLE = "#a855f7"
SELECTED = "#1e3a8a"

STATUS_COLOR = {Status.DETECTED: "#ef4444", Status.UNKNOWN: "#eab308", Status.CLEAN: "#22c55e"}

ASSETS = Path(__file__).resolve().parent.parent / "assets"
ICON_ICO = ASSETS / "icon.ico"
ICON_PNG = ASSETS / "icon.png"
ICON_SMALL = ASSETS / "icon_64.png"


def score_color(score: int) -> str:
    if score >= 70:
        return STATUS_COLOR[Status.DETECTED]
    if score >= 30:
        return STATUS_COLOR[Status.UNKNOWN]
    return STATUS_COLOR[Status.CLEAN]
