"""Lista blanca de rutas y hashes marcados como seguros."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from .models import Finding
from .utils import expand_win_vars

TEMPLATE = {
    "_comment": "Rutas (admiten * y %VAR%) y hashes SHA-256 que consideras seguros.",
    "paths": [],
    "hashes": [],
}


def _norm(path: str) -> str:
    return expand_win_vars(path.strip().strip('"')).replace("/", "\\").lower()


class WhitelistError(ValueError):
    pass


class Whitelist:
    def __init__(self, paths: list[str] | None = None, hashes: list[str] | None = None) -> None:
        self.paths = [_norm(p) for p in (paths or []) if p]
        self.hashes = {h.strip().lower() for h in (hashes or []) if h}

    def __len__(self) -> int:
        return len(self.paths) + len(self.hashes)

    @classmethod
    def load(cls, file: Path, create: bool = True) -> Whitelist:
        if not file.exists():
            if create:
                file.write_text(json.dumps(TEMPLATE, indent=2), encoding="utf-8")
            return cls()
        try:
            data = json.loads(file.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError as e:
            raise WhitelistError(f"{file.name} no es JSON válido: {e}") from e
        if not isinstance(data, dict):
            raise WhitelistError(f"{file.name} debe ser un objeto con 'paths' y 'hashes'")
        return cls(data.get("paths", []), data.get("hashes", []))

    def matches(self, f: Finding) -> bool:
        if f.sha256 and f.sha256.lower() in self.hashes:
            return True
        p = _norm(f.path)
        if not p:
            return False
        return any(
            p == pat or fnmatch.fnmatchcase(p, pat) or (pat.endswith("\\") and p.startswith(pat)) for pat in self.paths
        )

    def filter(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        kept = [f for f in findings if not self.matches(f)]
        return kept, len(findings) - len(kept)
