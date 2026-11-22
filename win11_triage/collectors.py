"""Ejecución y parseo de autorunsc.exe y sigcheck.exe."""
from __future__ import annotations

import csv
import io
import os
import subprocess
from pathlib import Path

from .models import Finding

AUTORUNS_ARGS = ["-accepteula", "-nobanner", "-a", "*", "-c", "-h", "-s"]
# -s añadido para recorrer subcarpetas; -nobanner para que la salida sea CSV puro.
SIGCHECK_ARGS = ["-accepteula", "-nobanner", "-u", "-e", "-c", "-h", "-s"]


# ---------------------------------------------------------------- utilidades
def decode_output(raw: bytes) -> str:
    """Sysinternals suele emitir UTF-16 LE en modo CSV; a veces ANSI/UTF-8."""
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
    """Parsea el CSV empezando en la línea de cabecera que contiene header_marker."""
    offset = 0
    for line in text.splitlines(keepends=True):
        if header_marker in line:
            break
        offset += len(line)
    else:
        return []
    reader = csv.DictReader(io.StringIO(text[offset:]))
    rows = []
    for row in reader:
        rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items() if k})
    return rows


def _get(row: dict[str, str], *keys: str) -> str:
    for k in keys:
        if row.get(k):
            return row[k]
    return ""


def run_tool(exe: Path, args: list[str], timeout: int = 1800) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(
        [str(exe), *args], capture_output=True, timeout=timeout, creationflags=flags
    )
    out = decode_output(proc.stdout)
    if proc.returncode not in (0, 1) and not out.strip():
        raise RuntimeError(
            f"{exe.name} terminó con código {proc.returncode}: {decode_output(proc.stderr).strip()}"
        )
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
            continue  # filas de cabecera de sección
        signer = row.get("Signer", "")
        if not is_non_microsoft(signer):
            continue
        path = _get(row, "Image Path", "Launch String")
        findings.append(
            Finding(
                source="autoruns",
                name=entry,
                path=path,
                publisher=_get(row, "Company", "Signer") or "(desconocido)",
                signature=signer or "(sin firma)",
                sha256=_get(row, "SHA-256", "SHA256").lower(),
                category=row.get("Category", ""),
                location=row.get("Entry Location", ""),
                signed_ok=signer.lower().startswith("(verified)"),
            )
        )
    return findings


def collect_autoruns(exe: Path) -> list[Finding]:
    return parse_autoruns(run_tool(exe, AUTORUNS_ARGS))


# ---------------------------------------------------------------- sigcheck
def user_scan_targets() -> list[Path]:
    targets = []
    local = os.environ.get("LOCALAPPDATA")
    roaming = os.environ.get("APPDATA")
    if local:
        targets.append(Path(local) / "Temp")
    if roaming:
        targets.append(Path(roaming))
    return targets


def parse_sigcheck(text: str, folder: str = "") -> list[Finding]:
    findings = []
    for row in parse_csv(text, "Verified"):
        path = _get(row, "Path")
        verified = row.get("Verified", "")
        if not path or verified.lower() == "signed":
            continue
        pub = next(
            (v for v in (row.get("Publisher", ""), row.get("Company", "")) if v and v.lower() != "n/a"),
            "",
        )
        findings.append(
            Finding(
                source="sigcheck",
                name=Path(path.replace("\\", "/")).name,
                path=path,
                publisher=pub or "(desconocido)",
                signature=verified or "(sin firma)",
                sha256=_get(row, "SHA256", "SHA-256").lower(),
                category="Ejecutable/DLL sin firma",
                location=folder,
            )
        )
    return findings


def collect_sigcheck(exe: Path, folder: Path) -> list[Finding]:
    return parse_sigcheck(run_tool(exe, [*SIGCHECK_ARGS, str(folder)]), str(folder))
