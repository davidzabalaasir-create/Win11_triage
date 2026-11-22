"""Cliente mínimo de VirusTotal API v3 con caché local y control de tasa."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

import requests
from rich.console import Console

API_URL = "https://www.virustotal.com/api/v3/files/{}"
GUI_URL = "https://www.virustotal.com/gui/file/{}"
NOT_FOUND_TTL = timedelta(days=7)  # los "no encontrado" se reconsultan pasada una semana


class VTAuthError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VTClient:
    def __init__(
        self,
        api_key: str,
        cache_file: Path,
        console: Console,
        interval: float = 15.0,
        simulator: Optional[Callable[[str], dict]] = None,
        persist: bool = True,
    ):
        self.api_key = api_key
        self.cache_file = cache_file
        self.console = console
        self.interval = interval
        self.simulator = simulator
        self.persist = persist
        self._last_request = 0.0
        self.stats = {"cache": 0, "network": 0, "errors": 0}
        self.cache: dict[str, dict] = {}
        if cache_file.exists():
            try:
                self.cache = json.loads(cache_file.read_text(encoding="utf-8") or "{}")
            except json.JSONDecodeError:
                console.print(f"[yellow]Caché corrupta ({cache_file.name}); se ignora.[/]")

    # ---------------------------------------------------------- caché
    def _cached(self, sha256: str) -> Optional[dict]:
        hit = self.cache.get(sha256)
        if not hit:
            return None
        if not hit.get("found"):
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(hit["queried_at"])
                if age > NOT_FOUND_TTL:
                    return None
            except (KeyError, ValueError):
                return None
        return hit

    def save(self) -> None:
        if self.persist:
            self.cache_file.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")

    # ---------------------------------------------------------- rate limit
    def _wait_turn(self) -> None:
        remaining = self.interval - (time.monotonic() - self._last_request)
        if self._last_request and remaining > 0:
            with self.console.status("") as status:
                while remaining > 0:
                    status.update(f"[cyan]Rate-limit VirusTotal: esperando {remaining:4.1f}s…")
                    time.sleep(min(0.5, remaining))
                    remaining = self.interval - (time.monotonic() - self._last_request)
        self._last_request = time.monotonic()

    # ---------------------------------------------------------- consulta
    def _request(self, sha256: str) -> dict:
        if self.simulator:
            return self.simulator(sha256)
        for attempt in range(2):
            r = requests.get(
                API_URL.format(sha256), headers={"x-apikey": self.api_key}, timeout=30
            )
            if r.status_code == 200:
                attrs = r.json()["data"]["attributes"]
                st = attrs.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "malicious": st.get("malicious", 0),
                    "suspicious": st.get("suspicious", 0),
                    "harmless": st.get("harmless", 0),
                    "undetected": st.get("undetected", 0),
                    "total": sum(v for v in st.values() if isinstance(v, int)),
                    "label": attrs.get("popular_threat_classification", {}).get(
                        "suggested_threat_label", ""
                    ),
                    "names": attrs.get("names", [])[:3],
                }
            if r.status_code == 404:
                return {"found": False}
            if r.status_code in (401, 403):
                raise VTAuthError("API key inválida o sin permisos (HTTP %d)" % r.status_code)
            if r.status_code == 429 and attempt == 0:
                self.console.print("[yellow]Cuota excedida (429). Esperando 60s…[/]")
                time.sleep(60)
                self._last_request = time.monotonic()
                continue
            return {"error": f"HTTP {r.status_code}"}
        return {"error": "HTTP 429"}

    def lookup(self, sha256: str) -> dict:
        sha256 = sha256.lower()
        hit = self._cached(sha256)
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
        self.save()  # guardado incremental: si se interrumpe no se pierde nada
        return {**result, "cached": False}
