"""Idiomas: español (original) e inglés.

El texto en español es la clave: ``t("Nuevo análisis")`` devuelve «New scan» si el idioma es inglés y
el propio texto si no hay traducción. Así el código sigue siendo legible y una traducción que falte
nunca rompe nada. Los textos con partes variables se traducen con patrones (``PATTERNS``).

Idioma: ``--lang`` (CLI), Ajustes → Apariencia (GUI) o la variable ``WIN11_TRIAGE_LANG`` (es | en).
"""

from __future__ import annotations

import os
import re
from typing import Any

LANGUAGES = {"es": "Español", "en": "English"}
_lang = os.environ.get("WIN11_TRIAGE_LANG", "es").lower()[:2]
if _lang not in LANGUAGES:
    _lang = "es"


def set_language(code: str | None) -> str:
    global _lang
    code = (code or "es").lower()[:2]
    _lang = code if code in LANGUAGES else "es"
    return _lang


def get_language() -> str:
    return _lang


def t(text: str, **fmt: Any) -> str:
    """Traduce ``text`` (español) al idioma activo. ``fmt`` rellena marcadores {nombre}."""
    out = text
    if _lang == "en" and text:
        from .i18n_en import EN, PATTERNS

        hit = EN.get(text)
        if hit is None:
            stripped = text.strip()
            if stripped and stripped != text and stripped in EN:
                hit = text.replace(stripped, EN[stripped])
        if hit is None:
            for rx, repl in PATTERNS:
                m = rx.fullmatch(text)
                if m:
                    hit = repl.format(*m.groups())
                    break
        out = hit if hit is not None else text
    return out.format(**fmt) if fmt else out


# ------------------------------------------------------------------ interfaz Tk
def translate_tree(widget: Any) -> None:
    """Traduce los textos estáticos de una ventana ya construida (etiquetas, botones, interruptores,
    segmentos y cabeceras de tablas). Los valores internos (los que lee el código) no cambian."""
    if _lang == "es":
        return
    _translate_one(widget)
    for child in widget.winfo_children():
        translate_tree(child)


def _translate_one(w: Any) -> None:
    cls = type(w).__name__
    try:
        if cls == "CTkSegmentedButton":
            for value, button in getattr(w, "_buttons_dict", {}).items():
                button.configure(text=t(str(value)))
            return
        if cls in ("CTkOptionMenu", "CTkComboBox", "CTkTextbox"):
            return  # su texto es un valor, no una etiqueta
        if cls == "Treeview":
            for col in ("#0", *w.cget("columns")):
                head = w.heading(col).get("text", "")
                if head:
                    w.heading(col, text=t(head))
            return
        if cls == "CTkEntry":
            ph = w.cget("placeholder_text")
            if ph:
                w.configure(placeholder_text=t(ph))
            return
        if hasattr(w, "cget"):
            text = w.cget("text")
            if isinstance(text, str) and text.strip():
                new = _with_prefix(text)
                if new != text:
                    w.configure(text=new)
    except Exception:  # widgets sin opción «text» o destruidos: se ignoran
        pass


_PREFIX = re.compile(r"^([^\w¿«(]*)(.*?)(\s*)$", re.S)


def _with_prefix(text: str) -> str:
    """Traduce respetando iconos o espacios iniciales («  Analizar», «▶ Exportar»)."""
    whole = t(text)
    if whole != text:
        return whole
    m = _PREFIX.match(text)
    if not m or not m.group(2):
        return text
    return f"{m.group(1)}{t(m.group(2))}{m.group(3)}"


def compile_patterns(items: list[tuple[str, str]]) -> list[tuple[re.Pattern[str], str]]:
    return [(re.compile(p, re.S), r) for p, r in items]
