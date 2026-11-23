"""Preferencias de la interfaz persistidas en <config-dir>/gui_settings.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FILE_NAME = "gui_settings.json"
DEFAULTS: dict[str, Any] = {
    "modules": {
        "autoruns": True,
        "scan_user": True,
        "processes": True,
        "events": True,
        "sigma": True,
        "browsers": True,
        "intel": False,
        "network": True,
        "static": True,
        "vt": True,
    },
    "event_days": 7,
    "vt_limit": "",
    "format": "HTML",
    "geometry": "",
    "appearance": "Oscuro",
    "notify": True,
    "alert_new": True,
    "schedule": "Desactivado",
    "schedule_at": "09:00",
    "language": "es",
}


def load(config_dir: Path) -> dict[str, Any]:
    data = json.loads(json.dumps(DEFAULTS))  # copia profunda
    try:
        stored = json.loads((config_dir / FILE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return data
    if isinstance(stored, dict):
        data["modules"].update({k: bool(v) for k, v in stored.get("modules", {}).items() if k in data["modules"]})
        for key in (
            "event_days",
            "vt_limit",
            "format",
            "geometry",
            "appearance",
            "notify",
            "alert_new",
            "schedule",
            "schedule_at",
            "language",
        ):
            if key in stored:
                data[key] = stored[key]
    return data


def save(config_dir: Path, data: dict[str, Any]) -> None:
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / FILE_NAME).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass  # preferencias: nunca deben impedir usar la app
