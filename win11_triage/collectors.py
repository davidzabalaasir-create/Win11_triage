"""Ejecución y parseo de autorunsc.exe, sigcheck.exe y tcpvcon.exe."""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import os
import subprocess
from pathlib import Path, PureWindowsPath

from .models import Connection, Finding
from .utils import expand_win_vars

log = logging.getLogger(__name__)

# -nobanner: salida CSV pura. -s en sigcheck: recorre subcarpetas.
AUTORUNS_ARGS = ["-accepteula", "-nobanner", "-a", "*", "-c", "-h", "-s"]
SIGCHECK_ARGS = ["-accepteula", "-nobanner", "-u", "-e", "-c", "-h", "-s"]
TCPVCON_ARGS = ["-accepteula", "-nobanner", "-c", "-n"]

DEFAULT_TIMEOUT = 1800  # autorunsc con -a * puede tardar varios minutos


class CollectorError(RuntimeError):
    """Fallo al ejecutar una herramienta externa."""


# ---------------------------------------------------------------- utilidades
def decode_output(raw: bytes) -> str:
    """Sysinternals emite UTF-16 LE en modo CSV (a veces ANSI/UTF-8)."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if len(raw) > 1 and raw[1:2] == b"\x00":
        return raw.decode("utf-16-le")
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def parse_csv(text: str, header_marker: str) -> list[dict[str, str]]:
    """Parsea el CSV a partir de la primera línea que contiene ``header_marker``."""
    offset = 0
    for line in text.splitlines(keepends=True):
        if header_marker in line:
            break
        offset += len(line)
    else:
        return []
    reader = csv.DictReader(io.StringIO(text[offset:]))
    return [{(k or "").strip(): (v or "").strip() for k, v in row.items() if isinstance(k, str)} for row in reader]


def _get(row: dict[str, str], *keys: str) -> str:
    return next((row[k] for k in keys if row.get(k)), "")


def _clean(value: str) -> str:
    return "" if value.lower() in ("", "n/a") else value


def sha256_file(path: str) -> str:
    """Calcula el SHA-256 si Sysinternals no lo dio (p. ej. sin acceso)."""
    p = Path(expand_win_vars(path.strip('"')))
    try:
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def run_tool(exe: Path, args: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    cmd = [str(exe), *args]
    log.debug("Ejecutando: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise CollectorError(f"{exe.name} superó el tiempo límite ({timeout}s)") from e
    except OSError as e:
        raise CollectorError(f"No se pudo ejecutar {exe.name}: {e}") from e
    out = decode_output(proc.stdout)
    if proc.returncode != 0 and not out.strip():
        err = decode_output(proc.stderr).strip()
        raise CollectorError(f"{exe.name} terminó con código {proc.returncode}: {err}")
    return out


# ---------------------------------------------------------------- autoruns
def is_non_microsoft(signer: str) -> bool:
    s = signer.strip().lower()
    if "(not verified)" in s:
        return True
    return not s.startswith("(verified) microsoft")


def parse_autoruns(text: str) -> list[Finding]:
    findings = []
    for row in parse_csv(text, "Entry Location"):
        entry = row.get("Entry", "")
        if not entry:
            continue  # filas de cabecera de sección (solo la ubicación)
        signer = row.get("Signer", "")
        if not is_non_microsoft(signer):
            continue
        path = _get(row, "Image Path", "Launch String")
        findings.append(
            Finding(
                source="autoruns",
                name=entry,
                path=path,
                publisher=_clean(_get(row, "Company", "Signer")) or "(desconocido)",
                signature=signer or "(sin firma)",
                sha256=_get(row, "SHA-256", "SHA256").lower(),
                category=row.get("Category", ""),
                location=row.get("Entry Location", ""),
                signed_ok=signer.lower().startswith("(verified)"),
            )
        )
    return findings


def collect_autoruns(exe: Path) -> list[Finding]:
    findings = parse_autoruns(run_tool(exe, AUTORUNS_ARGS))
    _fill_missing_hashes(findings)
    return findings


# ---------------------------------------------------------------- sigcheck
def user_scan_targets() -> list[Path]:
    env = (("LOCALAPPDATA", "Temp"), ("APPDATA", ""))
    return [Path(os.environ[var]) / sub for var, sub in env if os.environ.get(var)]


def parse_sigcheck(text: str, folder: str = "") -> list[Finding]:
    findings = []
    for row in parse_csv(text, "Verified"):
        path = row.get("Path", "")
        verified = row.get("Verified", "")
        if not path or verified.lower() == "signed":
            continue
        findings.append(
            Finding(
                source="sigcheck",
                name=PureWindowsPath(path).name,
                path=path,
                publisher=_clean(row.get("Publisher", "")) or _clean(row.get("Company", "")) or "(desconocido)",
                signature=verified or "(sin firma)",
                sha256=_get(row, "SHA256", "SHA-256").lower(),
                category="Ejecutable/DLL sin firma válida",
                location=folder,
            )
        )
    return findings


def collect_sigcheck(exe: Path, folder: Path) -> list[Finding]:
    findings = parse_sigcheck(run_tool(exe, [*SIGCHECK_ARGS, str(folder)]), str(folder))
    _fill_missing_hashes(findings)
    return findings


def _fill_missing_hashes(findings: list[Finding]) -> None:
    for f in findings:
        if not f.sha256 and f.path:
            f.sha256 = sha256_file(f.path)


# ---------------------------------------------------------------- tcpvcon
def parse_tcpvcon(text: str) -> list[Connection]:
    """tcpvcon -c: Protocolo,Proceso,PID,Estado,Local,Remoto (sin cabecera)."""
    conns = []
    for row in csv.reader(io.StringIO(text)):
        row = [c.strip() for c in row]
        if len(row) < 6 or not row[0].upper().startswith(("TCP", "UDP")):
            continue
        conns.append(Connection(*row[:6]))
    return conns


def collect_tcpvcon(exe: Path) -> list[Connection]:
    return parse_tcpvcon(run_tool(exe, TCPVCON_ARGS, timeout=120))


def correlate_connections(findings: list[Finding], conns: list[Connection]) -> int:
    """Asocia conexiones a hallazgos por nombre de imagen. Devuelve cuántos casan."""
    by_name: dict[str, list[Connection]] = {}
    for c in conns:
        by_name.setdefault(c.process.lower(), []).append(c)
    matched = 0
    for f in findings:
        f.connections = by_name.get(f.image_name, [])
        matched += bool(f.connections)
    return matched
