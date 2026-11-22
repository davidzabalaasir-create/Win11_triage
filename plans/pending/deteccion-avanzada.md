# Plan: detección avanzada para win11-triage (v2.0)

Estado: **PROPUESTA, pendiente de aprobación**. No se implementa nada hasta que se aprueben las decisiones de la sección «Preguntas».

## 0. Contexto (rellenado a partir del código actual, v1.2.0)

| Campo de la plantilla | Valor real |
|---|---|
| Lenguaje / stack | Python 3.10+, Rich, CustomTkinter, Sysinternals (`autorunsc`, `sigcheck`, `tcpvcon`), API v3 de VirusTotal |
| Tipo de análisis | **Triaje / respuesta a incidentes** en vivo sobre el propio equipo (sin detonación) |
| Destino | Windows 10/11, normalmente con privilegios de administrador |

### Limitaciones detectadas en el código actual

1. **Veredicto binario y poco explicativo.** `Finding.status` solo mira la firma y VirusTotal (`models.py`):
   - todo lo que no está firmado sale 🟡, aunque sea inofensivo, lo que genera **falsos positivos**;
   - un binario firmado que lanza `powershell -enc …` sale 🟢, lo que genera **falsos negativos**;
   - el informe no explica *por qué* algo es sospechoso.
2. **Persistencia sin contexto.** `autorunsc -a *` ya cubre Run, servicios, tareas, WMI, IFEO, Winlogon, AppInit, etc., pero no se puntúan:
   - la ubicación (Temp/AppData/ProgramData);
   - la línea de lanzamiento (LOLBins);
   - la categoría (por ejemplo, WMI es mucho más rara que Run).
3. **Red correlacionada por nombre.** `correlate_connections()` empareja por nombre de imagen, así que un `svchost.exe` falso en AppData se confunde con el legítimo.
4. **Sin análisis de procesos en ejecución.** No se detectan:
   - procesos en rutas escribibles por el usuario;
   - relaciones padre-hijo anómalas (Word → PowerShell);
   - suplantación de nombres de sistema;
   - binarios borrados del disco.
5. **Sin análisis estático.** Un hash desconocido en VT acaba en 🟡 sin más señales: no se mira entropía, empaquetadores, imports de inyección, YARA ni timestamps.
6. **Sin telemetría histórica.** No se leen los eventos 7045 (servicio instalado), 4698 (tarea creada) ni las detecciones de Defender (1116/1117).
7. **Salida sin semántica.** No hay puntuación, mapeo a MITRE ATT&CK ni evidencias estructuradas para automatizar.

---

## 1. Arquitectura propuesta

```
            ┌────────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
 colectores │ autoruns   │  │ sigcheck  │  │ procesos │  │ red      │  │ eventos  │
            │ (actual)   │  │ (actual)  │  │ (psutil) │  │ (psutil) │  │ (wevtutil)│
            └─────┬──────┘  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
                  └──────────────┬┴─────────────┴─────────────┴─────────────┘
                                 ▼  Finding (+ pid, cmdline, parent, created)
                   ┌──────────────────────────────┐
 enriquecedores    │ estático PE (pefile) · YARA  │  ← solo sobre ficheros señalados
                   │ VirusTotal (actual, caché)   │
                   └──────────────┬───────────────┘
                                  ▼
                   ┌──────────────────────────────┐
 motor de reglas   │ reglas → Signal(id, peso,    │  ← funciones puras, testeables
                   │   ATT&CK, evidencia)         │
                   │ puntuación 0–100 + veredicto │
                   └──────────────┬───────────────┘
                                  ▼
                   CLI · GUI · Markdown/HTML · JSON v2 (esquema versionado)
```

Principios de diseño:

- **Colectores ≠ detección.** Los colectores solo recogen datos; las reglas son **funciones puras** `Finding → Signal | None`. Se prueban con datos de ejemplo en Linux/CI, sin Windows.
- **Puntuación explicable.** Cada punto del score viene de una `Signal` con evidencia textual («línea de lanzamiento contiene `-enc` + base64 de 340 caracteres»).
- **Enriquecimiento caro, solo donde importa.** El análisis PE y YARA se ejecutan solo sobre lo que ya ha disparado alguna señal o no está firmado. Así se evita leer miles de ficheros.
- **VT pesa mucho, pero no decide solo.** Una detección en VT fuerza el 🔴. Que VT no conozca un hash **no** baja el score.

### Modelo de datos (aditivo, no rompe la v1)

```python
@dataclass(frozen=True)
class Signal:
    id: str  # "PERSIST_USER_WRITABLE_PATH"
    title: str  # texto para el informe, en español
    weight: int  # 0–100, se suman con saturación
    attack: str = ""  # "T1547.001"
    evidence: str = ""  # fragmento concreto que disparó la regla


# Finding gana: pid, ppid, parent_name, cmdline, created (datetime), signals: list[Signal]
# Finding.score = min(100, sum(weights)) ; el veredicto combina score y VT (ver Decisión D3)
```

---

## 2. Código y reglas listas para usar

> Todo es **defensivo**: solo lee y clasifica. No mata procesos, no borra ficheros y no sube muestras.

### 2.1 Heurísticas de ruta, nombre y línea de comandos (`win11_triage/rules/heuristics.py`)

```python
"""Reglas puras sobre un Finding. Cada una devuelve Signal o None."""

from __future__ import annotations

import difflib
import re
from pathlib import PureWindowsPath

from ..models import Finding, Signal

# Rutas donde un usuario sin privilegios puede escribir: el malware de commodity vive aquí.
USER_WRITABLE = re.compile(
    r"\\(users\\[^\\]+\\appdata|users\\public|programdata|windows\\temp|"
    r"\$recycle\.bin|perflogs|users\\[^\\]+\\(downloads|desktop|documents))\\",
    re.I,
)

# LOLBins usados como lanzadera (proxy execution / descarga). Patrón → (id, título, ATT&CK, peso)
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
        "regsvr32 carga scriptlet remoto (Squiblydoo)",
        "T1218.010",
        55,
    ),
    (
        re.compile(r"rundll32(\.exe)?\W+.*(javascript:|https?:|\\\\[^\\]+\\)", re.I),
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
]

# Binarios de sistema que solo deberían existir en System32/SysWOW64 (o \Windows para explorer).
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
SYSTEM_DIRS = re.compile(r"^[a-z]:\\windows\\(system32|syswow64|winsxs)\\", re.I)
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|com|bat|cmd|js|vbs|lnk)$", re.I)


def _cmd(f: Finding) -> str:
    return f"{f.path} {getattr(f, 'cmdline', '')}"


def user_writable_path(f: Finding) -> Signal | None:
    if USER_WRITABLE.search(f.path or ""):
        return Signal("PATH_USER_WRITABLE", "Ejecutable en carpeta escribible por el usuario", 20, "T1036", f.path)
    return None


def lolbin_cmdline(f: Finding) -> list[Signal]:
    text = _cmd(f)
    out = []
    for rx, sid, title, attack, weight in LOLBIN_PATTERNS:
        if m := rx.search(text):
            out.append(Signal(sid, title, weight, attack, m.group(0)[:200]))
    return out


def masquerading(f: Finding) -> Signal | None:
    name = PureWindowsPath(f.path.strip('"')).name.lower() if f.path else ""
    if not name:
        return None
    if name in SYSTEM_NAMES and not SYSTEM_DIRS.match(f.path.strip('"')):
        return Signal("MASQ_SYSTEM_NAME", f"{name} fuera de System32", 60, "T1036.005", f.path)
    close = difflib.get_close_matches(name, SYSTEM_NAMES, n=1, cutoff=0.85)
    if close and close[0] != name:  # scvhost.exe, svch0st.exe, lsas.exe…
        return Signal("MASQ_TYPOSQUAT", f"Nombre parecido a {close[0]}", 50, "T1036.005", name)
    if DOUBLE_EXT.search(name):
        return Signal("MASQ_DOUBLE_EXT", "Doble extensión engañosa", 45, "T1036.007", name)
    return None
```

### 2.2 Puntuación por categoría de persistencia (ATT&CK)

```python
# Categoría de autorunsc → (técnica ATT&CK, peso base). Lo raro pesa más.
PERSISTENCE_WEIGHT = {
    "Logon": ("T1547.001", 5),  # Run/RunOnce/Startup: muy común
    "Tasks": ("T1053.005", 10),
    "Services": ("T1543.003", 10),
    "Drivers": ("T1543.003", 15),
    "WMI": ("T1546.003", 40),  # suscripciones WMI: casi nunca legítimas en un PC
    "Image Hijacks": ("T1546.012", 40),  # IFEO Debugger / SilentProcessExit
    "Winlogon": ("T1547.004", 30),
    "AppInit": ("T1546.010", 35),
    "Explorer": ("T1546.015", 10),  # incluye COM hijack en HKCU
    "LSA Providers": ("T1547.002", 40),
    "Print Monitors": ("T1547.010", 35),
    "Boot Execute": ("T1547.001", 35),
    "Office": ("T1137", 25),
    "Network Providers": ("T1556.008", 35),
}
```

### 2.3 Procesos y red con PID exacto (`collectors_live.py`, requiere `psutil`)

```python
"""Procesos en ejecución y conexiones con PID → ruta real (sustituye la correlación por nombre)."""

import psutil

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
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
# Padres legítimos de procesos críticos: cualquier otro es una anomalía fuerte.
EXPECTED_PARENT = {
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "winlogon.exe": {"smss.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
}


def snapshot_processes() -> dict[int, dict]:
    procs = {}
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]):
        info = p.info
        info["cmdline"] = " ".join(info.get("cmdline") or [])
        procs[info["pid"]] = info  # sin privilegios, exe/cmdline pueden venir vacíos
    return procs


def parent_child_anomalies(procs: dict[int, dict]) -> list[tuple[dict, str, str, int]]:
    """Devuelve (proceso, id_señal, ATT&CK, peso) para relaciones padre-hijo sospechosas."""
    out = []
    for p in procs.values():
        name = (p.get("name") or "").lower()
        parent = (procs.get(p.get("ppid"), {}).get("name") or "").lower()
        if parent in OFFICE and name in SHELLS:
            out.append((p, "PROC_OFFICE_SPAWNS_SHELL", "T1204.002", 60))
        exp = EXPECTED_PARENT.get(name)
        if exp and parent and parent not in exp:
            out.append((p, "PROC_UNEXPECTED_PARENT", "T1036", 50))
    return out


def connections_by_pid() -> dict[int, list]:
    conns: dict[int, list] = {}
    for c in psutil.net_connections(kind="inet"):  # admin para ver los de todos los usuarios
        if c.pid and c.raddr:  # solo conexiones con extremo remoto
            conns.setdefault(c.pid, []).append(c)
    return conns
```

### 2.4 Análisis estático PE (`enrich/pe_static.py`, requiere `pefile`)

```python
"""Señales estáticas baratas sobre un PE. Solo lee el fichero: nunca lo ejecuta."""

import pefile

PACKER_SECTIONS = {"upx0", "upx1", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".enigma1", ".petite"}
INJECTION_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetThreadContext",
    "NtUnmapViewOfSection",
}


def pe_signals(path: str, max_bytes: int = 64 * 1024 * 1024) -> list[tuple[str, str, int, str]]:
    """Devuelve (id, ATT&CK, peso, evidencia)."""
    out = []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except (pefile.PEFormatError, OSError):
        return out
    names = {s.Name.rstrip(b"\0").decode(errors="ignore").lower() for s in pe.sections}
    if names & PACKER_SECTIONS:
        out.append(("PE_PACKER_SECTION", "T1027.002", 25, ", ".join(sorted(names & PACKER_SECTIONS))))
    high = [s for s in pe.sections if s.get_entropy() > 7.2 and s.SizeOfRawData > 4096]
    if high:
        out.append(("PE_HIGH_ENTROPY", "T1027.002", 20, f"{len(high)} sección(es) con entropía > 7.2"))
    imports = {
        imp.name.decode(errors="ignore")
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        for imp in e.imports
        if imp.name
    }
    inj = imports & INJECTION_APIS
    if len(inj) >= 3:
        out.append(("PE_INJECTION_IMPORTS", "T1055", 35, ", ".join(sorted(inj))))
    if 0 < len(imports) < 5 and high:
        out.append(("PE_FEW_IMPORTS_PACKED", "T1027.002", 15, f"{len(imports)} imports"))
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0 or ts > 4102444800:  # 0 o posterior a 2100: timestomping / builder
        out.append(("PE_BAD_TIMESTAMP", "T1070.006", 10, str(ts)))
    pe.close()
    return out
```

### 2.5 Eventos de Windows (sin dependencias: `wevtutil`)

```python
# Servicios instalados (System 7045), tareas creadas (Security 4698, requiere auditoría),
# detecciones de Defender (1116/1117). Últimos N días, salida XML parseada con ElementTree.
QUERIES = {
    "System": "*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= {ms}]]]",
    "Security": "*[System[(EventID=4698) and TimeCreated[timediff(@SystemTime) <= {ms}]]]",
    "Microsoft-Windows-Windows Defender/Operational": "*[System[(EventID=1116 or EventID=1117) and TimeCreated[timediff(@SystemTime) <= {ms}]]]",
}
# wevtutil qe "<log>" /q:"<query>" /f:xml /c:500 /rd:true
```

---

## 3. Reglas YARA e IoC

Fichero `win11_triage/rules/yara/win11_triage.yar`. Son reglas **heurísticas genéricas**, no de familia concreta: suman peso al score y nunca dan un veredicto por sí solas. El usuario puede añadir sus propias reglas en `<config-dir>/yara/*.yar`.

```yara
import "pe"

rule W11T_PS_EncodedOrHidden
{
    meta:
        description = "Script o acceso directo que lanza PowerShell codificado u oculto"
        mitre = "T1059.001"
        weight = 40
    strings:
        $ps  = "powershell" ascii wide nocase
        $enc = /\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $hid = /\s-w(indowstyle)?\s+h(idden)?\b/ ascii wide nocase
    condition:
        filesize < 5MB and $ps and ($enc or $hid)
}

rule W11T_Script_DownloadCradle
{
    meta:
        description = "Descarga + ejecución en memoria (cradle) en script"
        mitre = "T1105, T1059.001"
        weight = 40
    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "Net.WebClient" ascii wide nocase
        $d5 = "Start-BitsTransfer" ascii wide nocase
        $x1 = "IEX" ascii wide fullword
        $x2 = "Invoke-Expression" ascii wide nocase
        $x3 = "FromBase64String" ascii wide nocase
        $x4 = "Reflection.Assembly" ascii wide nocase
    condition:
        filesize < 2MB and 1 of ($d*) and 1 of ($x*)
}

rule W11T_LOLBin_ProxyExecution
{
    meta:
        description = "Uso de LOLBins para ejecutar o descargar contenido remoto"
        mitre = "T1218, T1140, T1197"
        weight = 45
    strings:
        $mshta = /mshta(\.exe)?["']?\s+["']?(https?|javascript|vbscript):/ ascii wide nocase
        $regsv = /regsvr32(\.exe)?["']?\s+.{0,60}\/i:\s*https?:/ ascii wide nocase
        $cert  = /certutil(\.exe)?["']?\s+.{0,30}-(urlcache|decode)/ ascii wide nocase
        $bits  = /bitsadmin(\.exe)?["']?\s+.{0,30}\/transfer/ ascii wide nocase
        $rdll  = /rundll32(\.exe)?["']?\s+.{0,60}javascript:/ ascii wide nocase
    condition:
        filesize < 5MB and any of them
}

rule W11T_Script_HeavyObfuscation
{
    meta:
        description = "VBS/JS con ofuscación por códigos de carácter y evaluación dinámica"
        mitre = "T1027"
        weight = 30
    strings:
        $chr  = "Chr(" ascii wide nocase
        $fcc  = "String.fromCharCode" ascii wide nocase
        $ev1  = "eval(" ascii wide nocase
        $ev2  = "Execute(" ascii wide nocase
        $ev3  = "ExecuteGlobal" ascii wide nocase
    condition:
        filesize < 2MB and (#chr > 50 or #fcc > 20) and any of ($ev*)
}

rule W11T_LNK_ShellLauncher
{
    meta:
        description = "Acceso directo (.lnk) que lanza un intérprete con argumentos"
        mitre = "T1204.002, T1547.009"
        weight = 35
    strings:
        $a = "powershell" ascii wide nocase
        $b = "cmd.exe" ascii wide nocase
        $c = "mshta" ascii wide nocase
        $d = "wscript" ascii wide nocase
        $h = "hidden" ascii wide nocase
        $e = "-enc" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and 1 of ($a, $b, $c, $d) and 1 of ($h, $e)
}

rule W11T_PE_PackedUPX
{
    meta:
        description = "PE empaquetado con UPX (muchas herramientas legítimas también lo usan)"
        mitre = "T1027.002"
        weight = 15
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.sections : ( s.name == "UPX0" or s.name == "UPX1" )
}

rule W11T_PE_ProcessInjectionImports
{
    meta:
        description = "Imports clásicos de inyección en procesos remotos"
        mitre = "T1055"
        weight = 30
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        ( pe.imports("kernel32.dll", "CreateRemoteThread") or
          pe.imports("kernel32.dll", "QueueUserAPC") or
          pe.imports("ntdll.dll", "NtCreateThreadEx") )
}
```

### IoC de comportamiento (se incluyen en `rules/ioc.json`)

| Tipo | Indicador | ATT&CK |
|---|---|---|
| Ruta | `%APPDATA%\*.exe`, `%LOCALAPPDATA%\Temp\*.exe`, `%PUBLIC%\*`, `C:\ProgramData\*.exe` (raíz), `C:\Windows\Temp\*.exe`, `C:\PerfLogs\*` | T1036 |
| Registro | `HKCU\…\Run`, `HKLM\…\Run(Once)`, `…\Winlogon\Shell` / `Userinit` con valores extra, `…\Image File Execution Options\*\Debugger`, `…\SilentProcessExit\*`, `HKCU\Software\Classes\CLSID\*\InprocServer32` (COM hijack), `…\Windows\AppInit_DLLs`, `HKLM\SYSTEM\…\Lsa\Security Packages` | T1547/T1546 |
| WMI | `__EventFilter` + `CommandLineEventConsumer`/`ActiveScriptEventConsumer` + `__FilterToConsumerBinding` | T1546.003 |
| Tareas | Acción en ruta de usuario, disparador «al iniciar sesión», ocultas (`Hidden=true`), autor vacío | T1053.005 |
| Servicios | `ImagePath` fuera de `System32`/`Program Files`, `cmd /c` o `powershell` en `ImagePath` | T1543.003 |
| Padre → hijo | Office → shell/LOLBin; `wmiprvse.exe` → `powershell.exe`; `explorer.exe` → `mshta.exe` con URL; `svchost.exe` sin padre `services.exe` | T1204/T1047 |
| Línea de comandos | `-enc`, `-w hidden`, `IEX`, `DownloadString`, `/i:http`, `-urlcache`, `javascript:` | T1059/T1218 |
| Eventos | 7045 (servicio nuevo), 4698 (tarea nueva), 1116/1117 (Defender), Sysmon 1/3/11/13/19-21 si está instalado | — |

---

## 4. Formato de salida JSON v2 (aditivo y versionado)

Los campos actuales de la v1 se mantienen y se añaden los nuevos. Se publicará un `docs/schema/triage-v2.json` (JSON Schema) para validar en pipelines o SIEM.

```json
{
  "schema_version": 2,
  "tool": "win11-triage", "version": "2.0.0",
  "host": "PC-01", "user": "ana", "admin": true,
  "started": "2026-11-22T13:15:11", "finished": "2026-11-22T13:21:40",
  "summary": {"DETECTADO": 2, "DESCONOCIDO": 5, "LIMPIO": 31, "max_score": 95},
  "findings": [{
    "id": "autoruns:7f3c…",                      // estable entre ejecuciones (para diff/historial)
    "source": "autoruns", "category": "Logon",
    "name": "OneSyncHelper",
    "path": "C:\\Users\\ana\\AppData\\Roaming\\OneSync\\syncsvc.exe",
    "cmdline": "\"…\\syncsvc.exe\" /silent",
    "sha256": "196c…", "signature": "(Not verified) OneSync Ltd",
    "status": "DETECTADO", "score": 95,
    "signals": [
      {"id": "PATH_USER_WRITABLE", "weight": 20, "attack": "T1036",   "evidence": "\\AppData\\Roaming\\"},
      {"id": "PERSIST_LOGON",      "weight": 5,  "attack": "T1547.001","evidence": "HKCU\\…\\Run"},
      {"id": "PE_HIGH_ENTROPY",    "weight": 20, "attack": "T1027.002","evidence": "2 secciones > 7.2"},
      {"id": "VT_DETECTED",        "weight": 100,"attack": "",         "evidence": "23/72 motores"}
    ],
    "attack": ["T1036", "T1547.001", "T1027.002"],
    "vt": {"malicious": 23, "total": 72, "link": "https://www.virustotal.com/gui/file/196c…"},
    "process": {"pid": 4120, "ppid": 1888, "parent": "explorer.exe"},
    "connections": [{"remote": "185.220.101.7:443", "state": "ESTABLISHED"}]
  }]
}
```

El informe HTML/Markdown añade:

- una columna **Puntuación** y un apartado **«Por qué»** con las señales de cada elemento;
- una tabla de técnicas ATT&CK observadas;
- la sección **«Prioriza esto primero»** con los 5 elementos de mayor puntuación.

---

## 5. Limitaciones y falsos positivos a vigilar

| Señal | Falsos positivos típicos | Mitigación |
|---|---|---|
| Ruta escribible por el usuario | Teams, Zoom, Discord, Slack, Spotify, OneDrive (todos en `%LOCALAPPDATA%`), Chrome/Edge updaters | Peso bajo (20). Firma válida de terceros resta. `whitelist.json` por editor |
| Sin firma | Herramientas internas, scripts `.bat/.ps1`, juegos indie, drivers de hardware antiguo | Sin firma solo suma; nunca es 🔴 por sí sola |
| UPX/entropía alta | Instaladores (NSIS, Inno), herramientas portables, protectores anti-trampas de juegos | Peso 15–20; requiere otra señal para pasar de 🟡 |
| Imports de inyección | Depuradores, antivirus/EDR, overlays (Discord, NVIDIA, Steam), accesibilidad | Combinar con ruta/firma; whitelist por editor |
| PowerShell oculto o `-enc` | Intune/SCCM, scripts de inicio corporativos, agentes RMM | Whitelist por hash del script o por línea exacta |
| WMI / IFEO | Software de gestión (SCCM usa WMI); IFEO lo usan depuradores y Application Verifier | Peso alto, pero mostrar evidencia completa |
| Office → shell | Macros corporativas legítimas, complementos | Reducir si el editor del binario hijo está firmado por Microsoft y la línea no tiene LOLBin |
| Masquerading por similitud | Nombres cortos legítimos que se parecen | Umbral 0.85 + lista de excepciones |
| VT «no encontrado» | Binarios propios o compilados localmente (normal) | No suma ni resta |

### Limitaciones del enfoque (honestas)

- **Rootkits y malware en memoria**: sin acceso a kernel ni a memoria, un rootkit puede ocultarse de `autorunsc` y `psutil`. Fuera de alcance (Volatility o un EDR).
- **Sin privilegios** se pierden procesos de otros usuarios, servicios protegidos y el log de seguridad. La GUI ya avisa y ofrece reiniciar como administrador.
- **Antievasión**: la herramienta no ejecuta muestras, así que no le afecta la evasión de sandbox. Tampoco detecta lo que solo se manifiesta en ejecución.
- **Herramientas de Sysinternals**: el malware puede comprobar si `autorunsc`/`procexp` están en ejecución. Para triaje en vivo se asume este riesgo.
- **YARA sobre muchos ficheros es lento**: se limita a hallazgos ya señalados y a un tamaño máximo (por defecto 50 MB).
- **El evento 4698** requiere la auditoría de «Otros eventos de objetos» activada. Si no lo está, se informa como «no disponible» y no como «sin tareas».

---

## Fases

Tamaños: S = 1–3 archivos, M = 4–6 archivos. Cada fase deja la CI en verde.

### Fase 0: cerrar el trabajo en curso de la GUI (Size: S)
Ya hechos sin commitear: el informe HTML (`--format html|all`), la carga de informes JSON para el historial y el logo.
- Aceptación: commit de `report.py` (HTML + `load_json`), el logo en `assets/` y sus tests. La GUI ampliada **se aplaza a la Fase 7** para mostrar ya score y señales.
- Verificación: `pytest -q` y `win11-triage --dry-run --format all`.
- Bloqueado por: decisión D1.

### Fase 1: modelo `Signal` + motor de reglas + puntuación (Size: M)
- Aceptación: `Finding.signals` y `Finding.score`; registro de reglas; el veredicto usa la regla D3; JSON `schema_version: 2` aditivo.
- Verificación: `pytest tests/test_rules_engine.py`.
- Archivos: `models.py`, `rules/__init__.py`, `rules/engine.py`, `engine.py`, `report.py`.
- Bloqueado por: Fase 0.

### Fase 2: heurísticas de ruta, línea de comandos, masquerading y categoría ATT&CK (Size: S)
- Aceptación: las reglas de §2.1 y §2.2 con datos de ejemplo positivos y negativos (incluida la lista de falsos positivos de §5).
- Verificación: `pytest tests/test_heuristics.py`.
- Archivos: `rules/heuristics.py`, `rules/attack.py`, `samples/autorunsc_sample.csv` (ampliado).
- Bloqueado por: 1.1.

### Fase 3: procesos y red con `psutil` (Size: M)
- Aceptación: módulo `--processes`; `--network` usa PID → ruta real (tcpvcon queda como respaldo); anomalías padre-hijo.
- Verificación: `pytest tests/test_live.py` con `psutil` simulado y el dry-run con `samples/processes_sample.json`.
- Archivos: `collectors_live.py`, `engine.py`, `cli.py`, `samples/*`.
- Bloqueado por: Fase 1.

### Fase 4: análisis estático PE (Size: S)
- Aceptación: `pe_signals()` sobre hallazgos sin firma o con señales previas; límite de tamaño.
- Verificación: `pytest tests/test_pe_static.py` con PE mínimos generados en el test (sin muestras reales).
- Archivos: `enrich/pe_static.py`, `engine.py`.
- Bloqueado por: Fase 1.

### Fase 5: YARA opcional (Size: S)
- Aceptación: extra `[yara]`; reglas de §3 incluidas, más `<config-dir>/yara/*.yar`; si falta `yara-python`, aviso claro, no error.
- Verificación: `pytest tests/test_yara.py` (se omite sin `yara-python`) y `yara --version` en la CI de Windows.
- Archivos: `enrich/yara_scan.py`, `rules/yara/win11_triage.yar`.
- Bloqueado por: Fase 1.

### Fase 6: eventos de Windows y Defender (Size: S)
- Aceptación: módulo `--events [días]` con 7045, 4698 y 1116/1117; «no disponible» cuando falta auditoría o permisos.
- Verificación: `pytest tests/test_events.py` con XML de ejemplo.
- Archivos: `collectors_events.py`, `engine.py`, `samples/events_*.xml`.
- Bloqueado por: Fase 1.

### Fase 7: informes y GUI con score, señales y ATT&CK (Size: M)
- Aceptación: columna Puntuación; «Por qué» en el detalle; tabla ATT&CK; sección «Prioriza esto primero»; GUI ampliada (logo, panel con gráficos, historial, exportar CSV, menú contextual, atajos).
- Verificación: `pytest` (incluida la prueba de humo de la GUI) y capturas en `docs/`.
- Bloqueado por: Fases 2–6.

Frontera paralelizable tras la Fase 1: **2, 3, 4, 5 y 6** son independientes entre sí.

## Decisiones (propuestas, pendientes de confirmar)

| # | Decisión | Opción recomendada | Por qué |
|---|---|---|---|
| D1 | Orden de trabajo | Commitear lo hecho de la GUI (HTML, logo) y hacer **detección primero**; la GUI ampliada al final | La GUI nueva se diseña una sola vez, ya con score y señales |
| D2 | Dependencias | `psutil` y `pefile` obligatorias; `yara-python` como extra opcional `[yara]` | psutil y pefile son puro Python o tienen wheels para Windows; yara-python a veces da problemas al instalar |
| D3 | Veredicto | 🔴 si VT ≥ 1 motor **o** score ≥ 70 · 🟡 si 30–69 o sin firma · 🟢 si < 30 y (firmado o VT limpio) | Mantiene los 3 colores actuales y añade explicación |
| D4 | Telemetría de eventos | Incluir la Fase 6 (7045, 4698, Defender) | Muy barata y aporta contexto temporal |
| D5 | Defender | Solo **leer** detecciones existentes; no lanzar `MpCmdRun -Scan` | Un escaneo completo tarda decenas de minutos |
| D6 | JSON | v2 **aditivo** (`schema_version: 2`), sin romper campos de la v1 | No rompe a quien ya consuma el JSON |
| D7 | ATT&CK | Solo IDs y nombres embebidos, sin descargar la matriz | Funciona sin conexión |

## No especificado todavía
- Fase 3: anomalías de firma en módulos cargados (DLL sideloading). Es niebla: se investiga al empezar la fase (coste de enumerar módulos con psutil).
- Fase 7: diseño exacto del panel de gráficos; se valida con capturas.

## Siempre / Nunca
- **Siempre**:
  - solo lectura;
  - cada señal con evidencia;
  - datos de ejemplo y tests sin Windows;
  - funciona sin conexión salvo VirusTotal.
- **Nunca**:
  - eliminar, matar o poner en cuarentena nada;
  - subir ficheros a VirusTotal ni a ningún servicio;
  - ejecutar muestras;
  - incluir payloads ni muestras reales de malware en el repositorio;
  - desactivar Defender.

## Progreso
| Fase | Estado |
|---|---|
| 0. Cerrar trabajo GUI en curso | pendiente |
| 1. Motor de señales y score | pendiente |
| 2. Heurísticas + ATT&CK | pendiente |
| 3. Procesos y red (psutil) | pendiente |
| 4. Estático PE | pendiente |
| 5. YARA | pendiente |
| 6. Eventos y Defender | pendiente |
| 7. Informes y GUI | pendiente |
