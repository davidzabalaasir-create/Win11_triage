"""Reglas puras: reciben un Finding y devuelven Signal(s). Sin E/S, fáciles de probar.

Los pesos están calibrados para que una sola señal débil (sin firma, ruta de usuario)
nunca baste para el rojo: hacen falta varias señales o una fuerte (LOLBin, VT, Defender).
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from pathlib import PureWindowsPath

from ..models import Finding, Signal
from .attack import PERSISTENCE

# --------------------------------------------------------------------------- patrones
# Carpetas donde un usuario sin privilegios puede escribir: hábitat del malware de commodity.
USER_WRITABLE = re.compile(
    r"\\(users\\[^\\]+\\appdata|users\\public|programdata|windows\\temp|"
    r"\$recycle\.bin|perflogs|users\\[^\\]+\\(downloads|desktop|documents))\\",
    re.I,
)

# LOLBins usados como lanzadera: (regex, id, título, ATT&CK, peso)
LOLBIN_PATTERNS: list[tuple[re.Pattern[str], str, str, str, int]] = [
    (
        re.compile(r"powershell(\.exe)?\b.*\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", re.I),
        "CMD_PS_ENCODED",
        "PowerShell con comando codificado en Base64",
        "T1059.001",
        45,
    ),
    (
        re.compile(
            r"powershell(\.exe)?\b.*(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient)", re.I
        ),
        "CMD_PS_DOWNLOAD",
        "PowerShell descarga contenido de Internet",
        "T1105",
        40,
    ),
    (
        re.compile(r"powershell(\.exe)?\b.*\s-w(indowstyle)?\s+h(idden)?\b", re.I),
        "CMD_PS_HIDDEN",
        "PowerShell en ventana oculta",
        "T1564.003",
        20,
    ),
    (
        re.compile(r"mshta(\.exe)?\W+.*(https?:|javascript:|vbscript:)", re.I),
        "CMD_MSHTA_REMOTE",
        "mshta ejecuta script remoto o en línea",
        "T1218.005",
        50,
    ),
    (
        re.compile(r"regsvr32(\.exe)?\W+.*/i:\s*https?:", re.I),
        "CMD_REGSVR32_SCT",
        "regsvr32 carga un scriptlet remoto (Squiblydoo)",
        "T1218.010",
        55,
    ),
    (
        re.compile(r"rundll32(\.exe)?\W+.*(javascript:|https?:|\\\\[^\\\s]+\\)", re.I),
        "CMD_RUNDLL32_ABUSE",
        "rundll32 con script, URL o ruta UNC",
        "T1218.011",
        45,
    ),
    (
        re.compile(r"certutil(\.exe)?\W+.*-(urlcache|decode|decodehex)\b", re.I),
        "CMD_CERTUTIL",
        "certutil usado para descargar o decodificar",
        "T1140",
        45,
    ),
    (
        re.compile(r"bitsadmin(\.exe)?\W+.*/(transfer|addfile)\b", re.I),
        "CMD_BITSADMIN",
        "bitsadmin descarga ficheros",
        "T1197",
        35,
    ),
    (
        re.compile(r"(wscript|cscript)(\.exe)?\W+.*\.(js|jse|vbs|vbe|wsf)\b", re.I),
        "CMD_WSH_SCRIPT",
        "Windows Script Host ejecuta un script",
        "T1059.005",
        20,
    ),
    (
        re.compile(r"cmd(\.exe)?\s+/c\s+.*(powershell|mshta|certutil|bitsadmin|curl\s+.*https?:)", re.I),
        "CMD_CMD_CHAIN",
        "cmd /c encadena una herramienta de descarga o ejecución",
        "T1059.003",
        25,
    ),
]

# Binarios de sistema que solo deberían vivir en System32/SysWOW64.
SYSTEM_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "rundll32.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "spoolsv.exe",
}
# Nombres legítimos que se parecen a los anteriores y no deben marcarse como typosquat.
TYPOSQUAT_EXCEPTIONS = {"svchost.exe", "sihost.exe", "taskhost.exe", "lsaiso.exe", "dashost.exe"}
SYSTEM_DIRS = re.compile(r"^[a-z]:\\windows\\(system32|syswow64|winsxs|servicing)\\", re.I)
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rar)\.(exe|scr|com|bat|cmd|js|vbs|lnk|hta)$", re.I)

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe"}
SHELLS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}
EXPECTED_PARENT = {
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe", "svchost.exe"},
}

RECENT_DAYS = 7

# Categorías donde el binario lanzado suele ser legítimo y lo malicioso es *cómo* se usa:
# ahí una firma de Microsoft no aporta confianza.
HIJACK_CATEGORIES = {"wmi", "image hijacks"}
# Herramientas de accesibilidad de la pantalla de inicio de sesión (backdoor «sticky keys»).
ACCESSIBILITY = {
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
    "displayswitch.exe",
    "atbroker.exe",
}


def has_lolbin(text: str) -> bool:
    return any(rx.search(text) for rx, *_ in LOLBIN_PATTERNS)


def _clean_path(f: Finding) -> str:
    return (f.path or "").strip().strip('"')


# --------------------------------------------------------------------------- reglas
def signature(f: Finding) -> Iterable[Signal]:
    if f.source in ("process", "event", "sigma"):
        return []  # en estos orígenes no se verificó la firma
    sig = f.signature.lower()
    abused = f.category.strip().lower() in HIJACK_CATEGORIES or has_lolbin(f"{f.path} {f.cmdline}")
    if f.signed_ok or sig == "signed":
        if abused:  # binario legítimo usado con fines maliciosos: la firma no exculpa
            return []
        return [Signal("SIG_TRUSTED", "Firma digital válida", -15, "", f.signature)]
    return [Signal("SIG_UNSIGNED", "Sin firma digital válida", 10, "", f.signature)]


def user_writable_path(f: Finding) -> Iterable[Signal]:
    path = _clean_path(f)
    if USER_WRITABLE.search(path):
        return [Signal("PATH_USER_WRITABLE", "Ejecutable en carpeta escribible por el usuario", 20, "", path)]
    return []


def lolbin_cmdline(f: Finding) -> Iterable[Signal]:
    text = f"{f.path} {f.cmdline}"
    return [
        Signal(sid, title, weight, attack, m.group(0)[:200])
        for rx, sid, title, attack, weight in LOLBIN_PATTERNS
        if (m := rx.search(text))
    ]


def masquerading(f: Finding) -> Iterable[Signal]:
    path = _clean_path(f)
    name = PureWindowsPath(path).name.lower() if path else ""
    if not name.endswith((".exe", ".scr", ".com", ".dll", ".bat", ".cmd", ".js", ".vbs", ".lnk", ".hta")):
        return []
    if DOUBLE_EXT.search(name):
        return [Signal("MASQ_DOUBLE_EXT", "Doble extensión engañosa", 45, "T1036.007", name)]
    if name in SYSTEM_NAMES:
        if "\\" in path and not SYSTEM_DIRS.match(path):
            return [Signal("MASQ_SYSTEM_NAME", f"{name} fuera de System32", 60, "T1036.005", path)]
        return []
    close = difflib.get_close_matches(name, SYSTEM_NAMES, n=1, cutoff=0.85)
    if close and name not in TYPOSQUAT_EXCEPTIONS:
        return [Signal("MASQ_TYPOSQUAT", f"Nombre muy parecido a {close[0]}", 50, "T1036.005", name)]
    return []


def persistence_category(f: Finding) -> Iterable[Signal]:
    # Servicios (7045) y tareas (4698) recién creados también son persistencia.
    event_persistence = f.source == "event" and f.category.startswith(("Servicio", "Tarea"))
    if f.source != "autoruns" and not event_persistence:
        return []
    out = []
    tid, weight = PERSISTENCE.get(f.category.strip().lower(), ("", 0)) if f.source == "autoruns" else ("", 0)
    if tid:
        out.append(
            Signal(
                f"PERSIST_{f.category.upper().replace(' ', '_')}",
                f"Persistencia: {f.category}",
                weight,
                tid,
                f.location,
            )
        )
    if has_lolbin(f"{f.path} {f.cmdline}"):
        out.append(
            Signal(
                "PERSIST_LOLBIN", "La persistencia lanza un LOLBin con argumentos sospechosos", 30, "T1218", f.location
            )
        )
    if f.category.strip().lower() == "image hijacks" and f.name.strip().lower() in ACCESSIBILITY:
        out.append(
            Signal(
                "PERSIST_ACCESSIBILITY_BACKDOOR",
                f"IFEO secuestra {f.name} (puerta trasera en la pantalla de inicio)",
                60,
                "T1546.008",
                f"{f.name} → {f.path}",
            )
        )
    if f.path.lower().startswith("file not found"):
        out.append(
            Signal("PERSIST_FILE_MISSING", "La entrada apunta a un fichero que ya no existe", 15, "T1070", f.path)
        )
    return out


def recent_file(f: Finding, now: datetime | None = None) -> Iterable[Signal]:
    # Solo ficheros: un proceso arrancado o un evento leído «hace poco» no dice nada.
    if not f.created or f.source not in ("autoruns", "sigcheck"):
        return []
    try:
        created = datetime.fromisoformat(f.created)
    except ValueError:
        return []
    now = now or datetime.now(created.tzinfo)
    if timedelta(0) <= now - created <= timedelta(days=RECENT_DAYS):
        return [Signal("FILE_RECENT", f"Creado hace menos de {RECENT_DAYS} días", 10, "", f.created)]
    return []


def process_lineage(f: Finding) -> Iterable[Signal]:
    if f.source != "process":
        return []
    name, parent = f.image_name or f.name.lower(), f.parent.lower()
    out = []
    if parent in OFFICE and name in SHELLS:
        out.append(Signal("PROC_OFFICE_SPAWNS_SHELL", f"{parent} lanzó {name}", 60, "T1204.002", f"{parent} → {name}"))
    expected = EXPECTED_PARENT.get(name)
    if expected and parent and parent not in expected:
        out.append(Signal("PROC_UNEXPECTED_PARENT", f"{name} con padre inusual ({parent})", 50, "T1036", parent))
    return out


def vt_verdict(f: Finding) -> Iterable[Signal]:
    vt = f.vt or {}
    if not vt.get("found"):
        return []
    mal, sus, total = vt.get("malicious", 0), vt.get("suspicious", 0), vt.get("total", 0)
    if mal > 0:
        label = f" ({vt['label']})" if vt.get("label") else ""
        return [
            Signal("VT_DETECTED", "Detectado por antivirus en VirusTotal", 100, "", f"{mal}/{total} motores{label}")
        ]
    if sus > 0:
        return [Signal("VT_SUSPICIOUS", "Marcado como sospechoso en VirusTotal", 25, "", f"{sus}/{total} motores")]
    return [Signal("VT_CLEAN", "0 detecciones en VirusTotal", -10, "", f"0/{total} motores")]


Rule = Callable[[Finding], Iterable[Signal]]

#: Reglas que se aplican a todos los hallazgos tras recolectar (VT va aparte, al final).
BASE_RULES: list[Rule] = [
    signature,
    user_writable_path,
    lolbin_cmdline,
    masquerading,
    persistence_category,
    recent_file,
    process_lineage,
]
