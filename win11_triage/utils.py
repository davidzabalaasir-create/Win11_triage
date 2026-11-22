"""Utilidades compartidas."""

from __future__ import annotations

import os
import re

_WIN_VAR = re.compile(r"%([^%\\/]+)%")


def expand_win_vars(value: str) -> str:
    """Expande variables estilo Windows (%APPDATA%) en cualquier plataforma.

    Las variables desconocidas se dejan tal cual, igual que hace cmd.exe.
    """
    lookup = {k.upper(): v for k, v in os.environ.items()}
    return _WIN_VAR.sub(lambda m: lookup.get(m.group(1).upper(), m.group(0)), value)
