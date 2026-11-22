"""Cliente mínimo de VirusTotal API v3 con caché local y control de tasa."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from rich.console import Console

from . import __version__

log = logging.getLogger(__name__)

API_URL = "https://www.virustotal.com/api/v3/files/{}"
GUI_URL = "https://www.virustotal.com/gui/file/{}"
FREE_TIER_INTERVAL = 15.0  # 4 peticiones/minuto
NOT_FOUND_TTL = timedelta(days=7)  # los "no encontrado" se reconsultan pasada una semana
RETRY_AFTER_429 = 60

VTResult = dict[str, Any]


class VTAuthError(RuntimeError):
    """API key inválida o sin permisos: no tiene sentido seguir consultando."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_file_report(payload: dict[str, Any]) -> VTResult:
    attrs = payload["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": sum(v for v in stats.values() if isinstance(v, int)),
        "label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        "names": attrs.get("names", [])[:3],
    }


class VTClient:
    def __init__(
        self,
        api_key: str,
        cache_file: Path,
        console: Console,
        interval: float = FREE_TIER_INTERVAL,
        simulator: Callable[[str], VTResult] | None = None,
        persist: bool = True,
    ) -> None:
        self.cache_file = cache_file
        self.console = console
        self.interval = interval
        self.simulator = simulator
        self.persist = persist
        self._last_request = 0.0
        self.stats = {"cache": 0, "network": 0, "errors": 0, "skipped": 0}
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "User-Agent": f"win11-triage/{__version__}"})
        self.cache: dict[str, VTResult] = self._load_cache()

    # ---------------------------------------------------------- caché
    def _load_cache(self) -> dict[str, VTResult]:
        if not self.cache_file.exists():
            return {}
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8") or "{}")
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            self.console.print(f"[yellow]Caché ilegible ({self.cache_file.name}); se ignora.[/]")
            return {}

    def cached(self, sha256: str) -> VTResult | None:
        hit = self.cache.get(sha256.lower())
        if not hit:
            return None
        if not hit.get("found"):
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(hit["queried_at"])
            except (KeyError, ValueError):
                return None
            if age > NOT_FOUND_TTL:
                return None
        return hit

    def save(self) -> None:
        if not self.persist:
            return
        tmp = self.cache_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.cache_file)  # escritura atómica

    # ---------------------------------------------------------- rate limit
    def _wait_turn(self) -> None:
        remaining = self.interval - (time.monotonic() - self._last_request)
        if self._last_request and remaining > 0:
            with self.console.status("") as status:
                while remaining > 0:
                    status.update(f"[cyan]Límite de VirusTotal: esperando {remaining:4.1f}s…")
                    time.sleep(min(0.5, remaining))
                    remaining = self.interval - (time.monotonic() - self._last_request)
        self._last_request = time.monotonic()

    # ---------------------------------------------------------- consulta
    def _request(self, sha256: str) -> VTResult:
        if self.simulator:
            return self.simulator(sha256)
        for attempt in range(2):
            r = self.session.get(API_URL.format(sha256), timeout=30)
            log.debug("VT %s → HTTP %s", sha256, r.status_code)
            if r.status_code == 200:
                return parse_file_report(r.json())
            if r.status_code == 404:
                return {"found": False}
            if r.status_code in (401, 403):
                raise VTAuthError(f"API key inválida o sin permisos (HTTP {r.status_code})")
            if r.status_code == 429 and attempt == 0:
                self.console.print(f"[yellow]Cuota excedida (429). Esperando {RETRY_AFTER_429}s…[/]")
                time.sleep(RETRY_AFTER_429)
                self._last_request = time.monotonic()
                continue
            return {"error": f"HTTP {r.status_code}"}
        return {"error": "HTTP 429"}

    def lookup(self, sha256: str) -> VTResult:
        sha256 = sha256.lower()
        hit = self.cached(sha256)
        if hit:
            self.stats["cache"] += 1
            return {**hit, "cached": True}
        self._wait_turn()
        try:
            result = self._request(sha256)
        except requests.RequestException as e:
            result = {"error": type(e).__name__}
        if "error" in result:
            self.stats["errors"] += 1
            return result  # los errores no se cachean
        self.stats["network"] += 1
        result.update(queried_at=_now(), link=GUI_URL.format(sha256))
        self.cache[sha256] = result
        self.save()  # guardado incremental: una interrupción no pierde lo consultado
        return {**result, "cached": False}
