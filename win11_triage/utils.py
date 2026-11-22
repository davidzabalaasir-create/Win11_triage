"""Utilidades compartidas."""

from __future__ import annotations

import os
import re

_WIN_VAR = re.compile(r"%([^%\\/]+)%")

# Valores por defecto de Windows, para expandir rutas de informes/eventos también fuera de Windows.
_WIN_DEFAULTS = {
    "SYSTEMROOT": "C:\\Windows",
    "WINDIR": "C:\\Windows",
    "COMSPEC": "C:\\Windows\\System32\\cmd.exe",
    "PROGRAMFILES": "C:\\Program Files",
    "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
    "PROGRAMDATA": "C:\\ProgramData",
    "SYSTEMDRIVE": "C:",
}


def expand_win_vars(value: str) -> str:
    """Expande variables estilo Windows (%APPDATA%) en cualquier plataforma.

    Las variables desconocidas se dejan tal cual, igual que hace cmd.exe.
    """
    lookup = {**_WIN_DEFAULTS, **{k.upper(): v for k, v in os.environ.items()}}
    return _WIN_VAR.sub(lambda m: lookup.get(m.group(1).upper(), m.group(0)), value)
