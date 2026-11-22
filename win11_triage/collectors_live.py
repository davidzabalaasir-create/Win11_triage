"""Procesos en ejecución y conexiones de red con psutil.

A diferencia de tcpvcon (que solo da el nombre del proceso), psutil da PID → ruta exacta del
ejecutable, así que un ``svchost.exe`` falso en AppData ya no se confunde con el legítimo.
Solo lectura: no se termina ni se modifica ningún proceso.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .collectors import sha256_file
from .models import Connection, Finding, Signal
from .rules.heuristics import lolbin_cmdline, masquerading, process_lineage, user_writable_path

try:  # psutil es dependencia obligatoria, pero se degrada con elegancia si falta
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    created: str  # ISO 8601
    exe_missing: bool = False  # la imagen se borró del disco tras arrancar


def available() -> bool:
    return psutil is not None


# ------------------------------------------------------------------ recolección
def snapshot_processes() -> dict[int, ProcInfo]:
    procs: dict[int, ProcInfo] = {}
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "create_time"]
    for p in psutil.process_iter(attrs):
        i = p.info
        exe = i.get("exe") or ""
        created = datetime.fromtimestamp(i["create_time"]).isoformat(timespec="seconds") if i.get("create_time") else ""
        procs[i["pid"]] = ProcInfo(
            pid=i["pid"],
            ppid=i.get("ppid") or 0,
            name=(i.get("name") or "").lower(),
            exe=exe,
            cmdline=" ".join(i.get("cmdline") or []),
            created=created,
            exe_missing=bool(exe) and not os.path.exists(exe),
        )
    return procs


def _is_external(addr: str) -> bool:
    host = addr.rsplit(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_unspecified)


def snapshot_connections(procs: dict[int, ProcInfo]) -> list[Connection]:
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or not c.pid:
            continue  # solo conexiones con extremo remoto y proceso conocido
        remote = f"{c.raddr.ip}:{c.raddr.port}"
        if not _is_external(remote):
            continue
        proto = "TCP" if c.type == 1 else "UDP"  # socket.SOCK_STREAM == 1
        name = procs[c.pid].name if c.pid in procs else "?"
        conns.append(Connection(proto, name, str(c.pid), c.status, f"{c.laddr.ip}:{c.laddr.port}", remote))
    return conns


def parse_sample(data: dict[str, Any]) -> tuple[dict[int, ProcInfo], list[Connection]]:
    """Carga un snapshot de ejemplo (dry-run / tests) con el mismo formato que la recolección real."""
    procs = {p["pid"]: ProcInfo(**p) for p in data.get("processes", [])}
    conns = [Connection(**c) for c in data.get("connections", [])]
    return procs, conns


# ------------------------------------------------------------------ hallazgos
_SELECTORS = (user_writable_path, lolbin_cmdline, masquerading, process_lineage)


def process_findings(procs: dict[int, ProcInfo], compute_hashes: bool = True) -> list[Finding]:
    """Convierte en hallazgo solo los procesos con al menos una señal positiva.

    Las señales se recalculan después en el motor de reglas; aquí solo sirven para filtrar
    (listar los ~200 procesos de un equipo sería ruido).
    """
    out = []
    for p in procs.values():
        parent = procs[p.ppid].name if p.ppid in procs else ""
        f = Finding(
            source="process",
            name=p.name,
            path=p.exe,
            publisher="(no verificado)",
            signature="(no verificada)",
            sha256="",
            category="Proceso en ejecución",
            location=f"PID {p.pid} · padre {parent or '?'} ({p.ppid})",
            cmdline=p.cmdline,
            pid=p.pid,
            ppid=p.ppid,
            parent=parent,
            created=p.created,
        )
        positive = [s for rule in _SELECTORS for s in rule(f) if s.weight > 0]
        if p.exe_missing:
            positive.append(Signal("PROC_IMAGE_MISSING", "El ejecutable ya no existe en disco", 40, "T1070.004", p.exe))
            f.signals.append(positive[-1])  # no la produce ninguna regla base: se conserva
        if not positive:
            continue
        if compute_hashes and p.exe and not p.exe_missing:
            f.sha256 = sha256_file(p.exe)
        out.append(f)
    return out


def attach_connections(findings: list[Finding], conns: list[Connection], procs: dict[int, ProcInfo]) -> int:
    """Asocia conexiones por PID (procesos) o por ruta exacta del ejecutable (resto)."""
    by_pid: dict[str, list[Connection]] = {}
    for c in conns:
        by_pid.setdefault(c.pid, []).append(c)
    pids_by_exe: dict[str, list[int]] = {}
    for p in procs.values():
        if p.exe:
            pids_by_exe.setdefault(p.exe.strip('"').lower(), []).append(p.pid)

    matched = 0
    for f in findings:
        if f.pid is not None:
            found = by_pid.get(str(f.pid), [])
        else:
            pids = pids_by_exe.get(f.path.strip().strip('"').lower(), [])
            found = [c for pid in pids for c in by_pid.get(str(pid), [])]
        f.connections = found
        if found:
            matched += 1
            remotes = ", ".join(sorted({c.remote for c in found})[:3])
            f.signals.append(Signal("NET_ACTIVE", "Conexiones de red activas hacia el exterior", 10, "T1071", remotes))
    return matched
