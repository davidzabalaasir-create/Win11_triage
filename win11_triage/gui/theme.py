"""Sistema de diseño de la interfaz: color, tipografía, espaciado e iconos.

Reglas (ver docs de diseño):
- Base neutra + un único acento. El color de estado solo en badges, iconos y bordes.
- Rejilla de 4 px: usa siempre ``SPACE``.
- Rutas, hashes e IPs en monoespaciada.
"""

from __future__ import annotations

import tkinter.font as tkfont
from pathlib import Path

import customtkinter as ctk

from ..models import Status

# ------------------------------------------------------------------ color
# Cada token: (claro, oscuro). Los widgets de CustomTkinter aceptan la tupla directamente;
# Canvas y ttk usan ``c(token)``, que resuelve según el modo activo.
TOKENS: dict[str, tuple[str, str]] = {
    "bg": ("#F6F7F9", "#0E1116"),
    "surface": ("#FFFFFF", "#161B22"),
    "surface2": ("#F0F2F5", "#1C2330"),
    "border": ("#DDE1E7", "#2A3140"),
    "text": ("#1A1F26", "#E6EAF0"),
    "text2": ("#5B6573", "#9AA4B2"),
    "accent": ("#2563EB", "#3B82F6"),
    "accent_hover": ("#1D4ED8", "#2F6FDB"),
    "accent_soft": ("#DBE7FD", "#1A2B4A"),
    "danger": ("#D92D20", "#F25F5C"),
    "danger_soft": ("#FDE7E5", "#3A1F22"),
    "warning": ("#B54708", "#F5B83D"),
    "warning_soft": ("#FEF0C7", "#3A2F17"),
    "success": ("#067647", "#3CCB7F"),
    "success_soft": ("#DCFAE6", "#163325"),
    "info": ("#4F46E5", "#7C8CFF"),
    "info_soft": ("#E8E7FD", "#24254A"),
}

STATUS_TOKEN = {Status.DETECTED: "danger", Status.UNKNOWN: "warning", Status.CLEAN: "success"}
STATUS_LABEL = {Status.DETECTED: "Detectado", Status.UNKNOWN: "Sospechoso", Status.CLEAN: "Limpio"}


def T(token: str) -> tuple[str, str]:
    return TOKENS[token]


def is_dark() -> bool:
    return ctk.get_appearance_mode().lower() == "dark"


def c(token: str) -> str:
    """Color concreto del token en el modo actual (para Canvas y ttk)."""
    light, dark = TOKENS[token]
    return dark if is_dark() else light


def status_color(st: Status) -> str:
    return c(STATUS_TOKEN[st])


def score_token(score: int) -> str:
    if score >= 70:
        return "danger"
    if score >= 30:
        return "warning"
    return "success"


# ------------------------------------------------------------------ espaciado
SPACE = {"xs": 4, "s": 8, "m": 12, "l": 16, "xl": 24, "xxl": 32}
RADIUS = {"control": 8, "card": 12}
CONTROL_H = 36
ROW_H = 36


# ------------------------------------------------------------------ tipografía
_families: set[str] | None = None


def _available() -> set[str]:
    global _families
    if _families is None:
        try:
            _families = set(tkfont.families())
        except Exception:
            _families = set()
    return _families


def _pick(*names: str) -> str:
    fams = _available()
    return next((n for n in names if n in fams), names[-1])


def ui_family() -> str:
    return _pick("Segoe UI Variable Text", "Segoe UI", "Inter", "Noto Sans", "DejaVu Sans")


def mono_family() -> str:
    return _pick("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono")


# Escala tipográfica: (tamaño, peso)
TYPE = {
    "display": (28, "bold"),
    "title": (20, "bold"),
    "subtitle": (14, "bold"),
    "body": (13, "normal"),
    "body_bold": (13, "bold"),
    "caption": (12, "normal"),
    "caption_bold": (12, "bold"),
    "overline": (11, "bold"),
}


def font(style: str = "body") -> ctk.CTkFont:
    size, weight = TYPE[style]
    return ctk.CTkFont(family=ui_family(), size=size, weight=weight)


def mono(size: int = 12) -> ctk.CTkFont:
    return ctk.CTkFont(family=mono_family(), size=size)


def tk_font(style: str = "body") -> tuple[str, int, str]:
    size, weight = TYPE[style]
    return (ui_family(), size - 3 if size > 12 else size - 2, weight)  # ttk usa puntos, no píxeles


def tk_mono(size: int = 10) -> tuple[str, int]:
    return (mono_family(), size)


# ------------------------------------------------------------------ iconos
# Segoe Fluent Icons (Windows 11) → Segoe MDL2 Assets (Windows 10) → símbolos Unicode.
_GLYPHS = {
    "home": ("\ue80f", "⌂"),
    "findings": ("\ue7ba", "⚑"),
    "network": ("\ue968", "⇄"),
    "tree": ("\ue8fd", "⑂"),
    "history": ("\ue81c", "⟲"),
    "settings": ("\ue713", "⚙"),
    "play": ("\ue768", "▶"),
    "stop": ("\ue71a", "■"),
    "search": ("\ue721", "⌕"),
    "export": ("\uede1", "⇪"),
    "copy": ("\ue8c8", "⧉"),
    "open": ("\ue8a7", "↗"),
    "check": ("\ue73e", "✓"),
    "alert": ("\uea39", "✕"),
    "warning": ("\ue7ba", "!"),
    "info": ("\ue946", "i"),
    "more": ("\ue712", "⋯"),
    "folder": ("\ue8b7", "▤"),
    "shield": ("\uea18", "⛨"),
    "key": ("\ue8d7", "⚿"),
    "log": ("\ue9f9", "≡"),
    "close": ("\ue711", "✕"),
    "chevron": ("\ue76c", "›"),
    "undo": ("\ue7a7", "↶"),
}


def icon_family() -> str | None:
    fams = _available()
    return next((f for f in ("Segoe Fluent Icons", "Segoe MDL2 Assets") if f in fams), None)


def glyph(name: str) -> str:
    fluent, fallback = _GLYPHS[name]
    return fluent if icon_family() else fallback


def icon_font(size: int = 16) -> ctk.CTkFont:
    fam = icon_family()
    return ctk.CTkFont(family=fam, size=size) if fam else ctk.CTkFont(family=ui_family(), size=size)


# ------------------------------------------------------------------ recursos
ASSETS = Path(__file__).resolve().parent.parent / "assets"
ICON_ICO = ASSETS / "icon.ico"
ICON_PNG = ASSETS / "icon.png"
ICON_SMALL = ASSETS / "icon_64.png"


def elide_middle(text: str, max_chars: int = 52) -> str:
    """C:\\Users\\…\\syncsvc.exe: conserva el principio y el nombre del fichero."""
    if len(text) <= max_chars:
        return text
    keep = max_chars - 1
    head, tail = keep // 2 - 4, keep - (keep // 2 - 4)
    return f"{text[:head]}…{text[-tail:]}"
