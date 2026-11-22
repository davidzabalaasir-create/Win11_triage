"""Lista blanca de rutas y hashes marcados como seguros."""
from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path

from .models import Finding


def _norm(path: str) -> str:
    return os.path.expandvars(path).replace("/", "\\").strip().lower()


class Whitelist:
    def __init__(self, paths: list[str] | None = None, hashes: list[str] | None = None):
        self.paths = [_norm(p) for p in (paths or []) if p]
        self.hashes = {h.strip().lower() for h in (hashes or []) if h}

    @classmethod
    def load(cls, file: Path) -> "Whitelist":
        if not file.exists():
            file.write_text(
                json.dumps({"paths": [], "hashes": []}, indent=2), encoding="utf-8"
            )
            return cls()
        data = json.loads(file.read_text(encoding="utf-8") or "{}")
        return cls(data.get("paths", []), data.get("hashes", []))

    def matches(self, f: Finding) -> bool:
        if f.sha256 and f.sha256.lower() in self.hashes:
            return True
        p = _norm(f.path)
        if not p:
            return False
        for pattern in self.paths:
            if p == pattern or fnmatch.fnmatch(p, pattern):
                return True
            if pattern.endswith("\\") and p.startswith(pattern):
                return True
        return False

    def filter(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        kept = [f for f in findings if not self.matches(f)]
        return kept, len(findings) - len(kept)
