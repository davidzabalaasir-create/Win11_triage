"""Triaje remoto por WinRM (PowerShell Remoting), sin instalar nada en el equipo analizado.

Ejecuta ``remote/collect.ps1`` con ``Invoke-Command -ComputerName`` desde el equipo del analista y
convierte el JSON devuelto en hallazgos: persistencia (Run, Inicio, servicios, tareas, WMI, IFEO),
procesos y conexiones. Después se aplican las mismas reglas, VirusTotal y reputación que en local.

Requisitos: WinRM activo en el remoto (``Enable-PSRemoting``), puerto 5985/5986 accesible y una cuenta
administradora del remoto. Credenciales: las de tu sesión (dominio) o ``--remote-user`` (Windows las
pide en una ventana segura; nunca pasan por win11-triage).
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .collectors import decode_output, is_non_microsoft
from .collectors_live import ProcInfo
from .models import Connection, Finding
from .rules.heuristics import HIJACK_CATEGORIES, has_lolbin

SCRIPT = Path(__file__).resolve().parent / "remote" / "collect.ps1"
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")


class RemoteError(RuntimeError):
    pass


def valid_host(host: str) -> bool:
    """Nombre NetBIOS/DNS o IPv4: evita inyectar texto en la línea de PowerShell."""
    return bool(_HOST_RE.match(host))


def build_command(host: str, user: str | None = None, use_ssl: bool = False) -> list[str]:
    if not valid_host(host):
        raise RemoteError(f"Nombre de equipo no válido: {host!r}")
    if user is not None and not re.match(r"^[\w.\-\\@]{1,104}$", user):
        raise RemoteError(f"Usuario no válido: {user!r}")
    cred = f" -Credential (Get-Credential -UserName '{user}' -Message 'win11-triage: cuenta de {host}')" if user else ""
    ssl = " -UseSSL" if use_ssl else ""
    ps = f"Invoke-Command -ComputerName '{host}'{cred}{ssl} -FilePath '{SCRIPT}' -ErrorAction Stop"
    return ["powershell.exe", "-NoProfile", "-NonInteractive" if not user else "-NoLogo", "-Command", ps]


def collect(host: str, user: str | None = None, use_ssl: bool = False, timeout: int = 900) -> dict[str, Any]:
    try:
        proc = subprocess.run(build_command(host, user, use_ssl), capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise RemoteError("PowerShell no está disponible: el triaje remoto requiere Windows") from e
    except subprocess.TimeoutExpired as e:
        raise RemoteError(f"{host} no respondió en {timeout} s") from e
    out, err = decode_output(proc.stdout).strip(), decode_output(proc.stderr).strip()
    if proc.returncode != 0 or not out:
        hint = ""
        if "WinRM" in err or "cannot connect" in err.lower() or "no se puede conectar" in err.lower():
            hint = " (¿WinRM activo? En el remoto: Enable-PSRemoting -Force)"
        raise RemoteError((err.splitlines()[0] if err else f"PowerShell código {proc.returncode}") + hint)
    return parse_output(out)


def parse_output(text: str) -> dict[str, Any]:
    start = text.find("{")
    if start < 0:
        raise RemoteError("La respuesta del equipo remoto no es JSON")
    try:
        data = json.loads(text[start:])
    except ValueError as e:
        raise RemoteError(f"JSON remoto no válido: {e}") from e
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise RemoteError("Versión del script remoto no compatible")
    for key in ("processes", "connections", "autoruns"):  # ConvertTo-Json convierte listas de 1 en objeto
        value = data.get(key) or []
        data[key] = value if isinstance(value, list) else [value]
    return data


def autorun_findings(data: dict[str, Any]) -> list[Finding]:
    """Mismo criterio que con autorunsc: fuera lo firmado por Microsoft salvo abuso (LOLBin, secuestro)."""
    out = []
    for e in data.get("autoruns", []):
        signer, cmd, category = e.get("signer", ""), e.get("cmdline", ""), e.get("category", "")
        keep = is_non_microsoft(signer) or category.strip().lower() in HIJACK_CATEGORIES or has_lolbin(cmd)
        if not keep:
            continue
        out.append(
            Finding(
                source="autoruns",
                name=e.get("name", ""),
                path=e.get("path", ""),
                publisher=re.sub(r"^\((Not verified|Verified)\)\s*", "", signer) or "(desconocido)",
                signature=signer or "(sin firma)",
                sha256=(e.get("sha256") or "").lower(),
                category=category,
                location=e.get("location", ""),
                signed_ok=signer.startswith("(Verified)"),
                cmdline=cmd,
                created=e.get("created", ""),
            )
        )
    return out


def snapshot(data: dict[str, Any]) -> tuple[dict[int, ProcInfo], list[Connection]]:
    procs = {}
    for p in data.get("processes", []):
        try:
            procs[int(p["pid"])] = ProcInfo(
                pid=int(p["pid"]),
                ppid=int(p.get("ppid") or 0),
                name=str(p.get("name", "")),
                exe=str(p.get("exe") or ""),
                cmdline=str(p.get("cmdline") or ""),
                created=str(p.get("created") or ""),
                exe_missing=bool(p.get("exe_missing")),
            )
        except (KeyError, TypeError, ValueError):
            continue
    conns = [
        Connection(
            str(c.get("protocol", "TCP")),
            str(c.get("process", "")),
            str(c.get("pid", "")),
            str(c.get("state", "")),
            str(c.get("local", "")),
            str(c.get("remote", "")),
        )
        for c in data.get("connections", [])
    ]
    return procs, conns


def process_hashes(data: dict[str, Any]) -> dict[str, str]:
    """Hashes calculados en remoto para las rutas de persistencia (reutilizables en procesos)."""
    return {
        str(e.get("path", "")).lower(): str(e.get("sha256", "")).lower()
        for e in data.get("autoruns", [])
        if e.get("path") and e.get("sha256")
    }
