"""Reputación externa: AbuseIPDB (direcciones IP) y MalwareBazaar (hashes).

Ambas APIs son gratuitas con registro. Las claves se leen de ``ABUSEIPDB_API_KEY`` y
``MALWAREBAZAAR_API_KEY`` (.env). Las respuestas se guardan en ``intel_cache.json`` para no
repetir consultas: 1 día para IPs y 7 días para hashes. Solo se consultan IPs públicas.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from . import __version__
from .models import Finding, Signal

log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
IP_TTL = timedelta(days=1)
HASH_TTL = timedelta(days=7)
MAX_IPS = 60  # plan gratuito de AbuseIPDB: 1000 consultas/día
MAX_HASHES = 100
_IP_IN_TEXT = re.compile(r"→\s*([0-9a-fA-F.:]+?):\d+\b")

Lookup = Callable[[str], dict[str, Any]]


def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global


def remote_ip(remote: str) -> str:
    """'1.2.3.4:443' → '1.2.3.4'; '[2001:db8::1]:443' → '2001:db8::1'."""
    remote = remote.strip()
    if remote.startswith("["):
        return remote[1 : remote.find("]")]
    return remote.rsplit(":", 1)[0] if remote.count(":") == 1 else remote


def finding_ips(f: Finding) -> set[str]:
    ips = {remote_ip(c.remote) for c in f.connections}
    ips |= set(_IP_IN_TEXT.findall(f.cmdline or ""))  # conexiones de Sysmon (evento 3)
    return {ip for ip in ips if is_public_ip(ip)}


# ------------------------------------------------------------------ clientes HTTP
def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = f"win11-triage/{__version__}"
    return s


def abuseipdb_lookup(api_key: str, session: requests.Session | None = None) -> Lookup:
    s = session or _session()

    def lookup(ip: str) -> dict[str, Any]:
        r = s.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=20,
        )
        if r.status_code in (401, 403):
            raise PermissionError("AbuseIPDB rechazó la API key")
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "score": int(d.get("abuseConfidenceScore") or 0),
            "reports": int(d.get("totalReports") or 0),
            "country": d.get("countryCode") or "",
            "isp": d.get("isp") or "",
            "tor": bool(d.get("isTor")),
        }

    return lookup


def malwarebazaar_lookup(api_key: str, session: requests.Session | None = None) -> Lookup:
    s = session or _session()

    def lookup(sha256: str) -> dict[str, Any]:
        r = s.post(
            MALWAREBAZAAR_URL, data={"query": "get_info", "hash": sha256}, headers={"Auth-Key": api_key}, timeout=20
        )
        if r.status_code in (401, 403):
            raise PermissionError("MalwareBazaar rechazó la API key")
        r.raise_for_status()
        body = r.json()
        status = body.get("query_status", "")
        if status in ("hash_not_found", "no_results"):
            return {"found": False}
        if status != "ok":
            raise RuntimeError(f"MalwareBazaar: {status}")
        d = (body.get("data") or [{}])[0]
        return {
            "found": True,
            "signature": d.get("signature") or "",
            "tags": list(d.get("tags") or [])[:5],
            "first_seen": d.get("first_seen") or "",
        }

    return lookup


# ------------------------------------------------------------------ caché
class IntelCache:
    def __init__(self, path: Path, persist: bool = True) -> None:
        self.path, self.persist = path, persist
        self.data: dict[str, dict[str, Any]] = {"ip": {}, "hash": {}}
        if persist and path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                self.data.update({k: dict(v) for k, v in loaded.items() if k in self.data})
            except (OSError, ValueError, AttributeError) as e:
                log.warning("intel_cache.json ilegible, se ignora: %s", e)

    def get(self, kind: str, key: str, ttl: timedelta) -> dict[str, Any] | None:
        entry = self.data[kind].get(key)
        if not entry:
            return None
        try:
            when = datetime.fromisoformat(entry["checked"])
        except (KeyError, ValueError):
            return None
        return entry if datetime.now(timezone.utc) - when < ttl else None

    def put(self, kind: str, key: str, value: dict[str, Any]) -> dict[str, Any]:
        value = {**value, "checked": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.data[kind][key] = value
        return value

    def save(self) -> None:
        if self.persist:
            self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")


# ------------------------------------------------------------------ señales
def ip_signal(ip: str, info: dict[str, Any]) -> Signal | None:
    score = info.get("score", 0)
    where = " · ".join(x for x in (info.get("country"), info.get("isp")) if x)
    evidence = f"{ip} · {score}% confianza · {info.get('reports', 0)} denuncias" + (f" · {where}" if where else "")
    if info.get("tor"):
        evidence += " · nodo Tor"
    if score >= 75:
        return Signal("INTEL_IP_MALICIOUS", "IP con mala reputación en AbuseIPDB", 45, "T1071", evidence)
    if score >= 25 or info.get("tor"):
        return Signal("INTEL_IP_SUSPICIOUS", "IP denunciada en AbuseIPDB", 20, "T1071", evidence)
    return None


def hash_signal(info: dict[str, Any]) -> Signal | None:
    if not info.get("found"):
        return None
    fam = info.get("signature") or "familia desconocida"
    tags = ", ".join(info.get("tags") or [])
    evidence = (
        f"{fam}"
        + (f" · {tags}" if tags else "")
        + (f" · visto {info['first_seen'][:10]}" if info.get("first_seen") else "")
    )
    return Signal("INTEL_MB_KNOWN", "Hash conocido en MalwareBazaar", 80, "", evidence)


def _from_cache(
    kind: str, key: str, ttl: timedelta, cache: IntelCache, out: dict[str, dict[str, Any]], stats: dict[str, int]
) -> bool:
    hit = cache.get(kind, key, ttl)
    if hit is None:
        return False
    out[key] = hit
    stats["cache"] += 1
    return True


def enrich(
    findings: Iterable[Finding],
    ip_lookup: Lookup | None,
    hash_lookup: Lookup | None,
    cache: IntelCache,
    on_warn: Callable[[str], None] = lambda _m: None,
) -> dict[str, int]:
    """Añade señales INTEL_* a los hallazgos. Devuelve estadísticas de consultas."""
    findings = list(findings)
    stats = {"ips": 0, "ip_bad": 0, "hashes": 0, "hash_known": 0, "cache": 0, "network": 0}
    ip_results: dict[str, dict[str, Any]] = {}
    hash_results: dict[str, dict[str, Any]] = {}

    lock = threading.Lock()

    def resolve(kind: str, key: str, ttl: timedelta, fn: Lookup | None, out: dict[str, dict[str, Any]]) -> None:
        nonlocal ip_lookup, hash_lookup
        if key in out or fn is None:
            return
        hit = cache.get(kind, key, ttl)
        if hit is not None:
            stats["cache"] += 1
            out[key] = hit
            return
        try:
            value = fn(key)
            with lock:
                out[key] = cache.put(kind, key, value)
                stats["network"] += 1
        except PermissionError as e:
            on_warn(f"{e}: se omite el resto de consultas de ese servicio.")
            if kind == "ip":
                ip_lookup = None
            else:
                hash_lookup = None
        except (requests.RequestException, RuntimeError, ValueError) as e:
            on_warn(f"Reputación de {key} no disponible: {e}")

    ips = sorted({ip for f in findings for ip in finding_ips(f)})[:MAX_IPS]
    hashes = sorted({f.sha256.lower() for f in findings if len(f.sha256 or "") == 64})[:MAX_HASHES]
    # Primero lo que está en caché (instantáneo); lo demás, 4 consultas a la vez.
    ips_todo = [ip for ip in ips if not _from_cache("ip", ip, IP_TTL, cache, ip_results, stats)]
    hashes_todo = [h for h in hashes if not _from_cache("hash", h, HASH_TTL, cache, hash_results, stats)]
    # La primera consulta de cada servicio va sola: si la clave es mala no se lanzan las demás.
    if ips_todo:
        resolve("ip", ips_todo[0], IP_TTL, ip_lookup, ip_results)
    if hashes_todo:
        resolve("hash", hashes_todo[0], HASH_TTL, hash_lookup, hash_results)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="intel") as pool:
        list(pool.map(lambda ip: resolve("ip", ip, IP_TTL, ip_lookup, ip_results), ips_todo[1:]))
        list(pool.map(lambda h: resolve("hash", h, HASH_TTL, hash_lookup, hash_results), hashes_todo[1:]))
    cache.save()

    stats["ips"], stats["hashes"] = len(ip_results), len(hash_results)
    stats["ip_bad"] = sum(1 for v in ip_results.values() if v.get("score", 0) >= 75)
    stats["hash_known"] = sum(1 for v in hash_results.values() if v.get("found"))
    for f in findings:
        f.signals = [s for s in f.signals if not s.id.startswith("INTEL_")]
        best = max(
            (s for ip in finding_ips(f) if ip in ip_results for s in [ip_signal(ip, ip_results[ip])] if s),
            key=lambda s: s.weight,
            default=None,
        )
        f.add(best)
        if f.sha256 and f.sha256.lower() in hash_results:
            f.add(hash_signal(hash_results[f.sha256.lower()]))
    return stats


# ------------------------------------------------------------------ dry-run
DEMO_IPS = {
    "185.220.101.7": {"score": 100, "reports": 2140, "country": "DE", "isp": "Tor exit", "tor": True},
    "203.0.113.50": {"score": 87, "reports": 54, "country": "NL", "isp": "Demo Hosting"},
    "198.51.100.23": {"score": 30, "reports": 3, "country": "US", "isp": "Demo Cloud"},
}


def demo_ip_lookup(ip: str) -> dict[str, Any]:
    return DEMO_IPS.get(ip, {"score": 0, "reports": 0, "country": "", "isp": ""})


def demo_hash_lookup(known: set[str]) -> Lookup:
    def lookup(h: str) -> dict[str, Any]:
        if h in known:
            return {
                "found": True,
                "signature": "AsyncRAT",
                "tags": ["rat", "demo"],
                "first_seen": "2026-10-02 11:00:00",
            }
        return {"found": False}

    return lookup
