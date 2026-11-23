"""Revisión del analista: estado y notas por hallazgo, persistidos entre sesiones.

Se guardan en ``<config-dir>/review.json`` indexados por ``Finding.key``, así que la decisión
(«falso positivo», «confirmado»…) se conserva cuando el mismo elemento vuelve a aparecer.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

PENDING = "Pendiente"
STATES = (PENDING, "En revisión", "Falso positivo", "Confirmado")
STATE_TOKEN = {PENDING: "text2", "En revisión": "info", "Falso positivo": "success", "Confirmado": "danger"}
# Atajos de teclado en la tabla de hallazgos
STATE_KEYS = {"p": PENDING, "r": "En revisión", "f": "Falso positivo", "c": "Confirmado"}


class ReviewStore:
    FILE_NAME = "review.json"

    def __init__(self, config_dir: Path) -> None:
        self.path = config_dir / self.FILE_NAME
        self.data: dict[str, dict[str, Any]] = {}
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data = {k: v for k, v in loaded.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            pass

    def get(self, key: str) -> dict[str, Any]:
        return {"state": PENDING, "note": "", **self.data.get(key, {})}

    def state(self, key: str) -> str:
        return self.get(key)["state"]

    def set(self, key: str, *, state: str | None = None, note: str | None = None, name: str = "") -> dict[str, Any]:
        entry = self.get(key)
        if state is not None:
            if state not in STATES:
                raise ValueError(f"Estado no válido: {state}")
            entry["state"] = state
        if note is not None:
            entry["note"] = note.strip()
        entry["updated"] = datetime.now().isoformat(timespec="seconds")
        if name:
            entry["name"] = name
        if entry["state"] == PENDING and not entry["note"]:
            self.data.pop(key, None)  # nada que recordar
        else:
            self.data[key] = entry
        self.save()
        return entry

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def counts(self, keys: list[str]) -> dict[str, int]:
        out = dict.fromkeys(STATES, 0)
        for k in keys:
            out[self.state(k)] += 1
        return out
