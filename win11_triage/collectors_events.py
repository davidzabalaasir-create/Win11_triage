"""Eventos de Windows relevantes para persistencia y detecciones previas (vía wevtutil).

- System 7045: servicio instalado (técnica habitual de movimiento lateral y persistencia).
- Security 4698: tarea programada creada (requiere la auditoría «Otros eventos de objetos»).
- Defender 1116/1117: Microsoft Defender detectó una amenaza / actuó sobre ella.

Solo lectura. Si un registro no está disponible (sin permisos o sin auditoría) se informa
como «no disponible», nunca como «sin eventos».
"""

from __future__ import annotations

import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .collectors import decode_output
from .models import Finding, Signal
from .utils import expand_win_vars

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TASK_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

LOGS: list[tuple[str, tuple[int, ...]]] = [
    ("System", (7045,)),
    ("Security", (4698,)),
    ("Microsoft-Windows-Windows Defender/Operational", (1116, 1117)),
]


@dataclass
class Event:
    log: str
    event_id: int
    time: str
    data: dict[str, str] = field(default_factory=dict)


# ------------------------------------------------------------------ consulta
def build_query(ids: tuple[int, ...], days: int) -> str:
    cond = " or ".join(f"EventID={i}" for i in ids)
    ms = days * 24 * 3600 * 1000
    return f"*[System[({cond}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"


def query_log(log: str, ids: tuple[int, ...], days: int, max_events: int = 500) -> str:
    cmd = ["wevtutil", "qe", log, f"/q:{build_query(ids, days)}", "/f:xml", f"/c:{max_events}", "/rd:true"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        timeout=120,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(decode_output(proc.stderr).strip() or f"wevtutil código {proc.returncode}")
    return decode_output(proc.stdout)


def parse_events(xml_text: str) -> list[Event]:
    """wevtutil emite elementos <Event> concatenados sin raíz: se envuelven para parsear."""
    text = re.sub(r"<\?xml[^>]*\?>", "", xml_text).strip()
    if not text:
        return []
    root = ET.fromstring(f"<Events>{text}</Events>")
    events = []
    for ev in root.findall("e:Event", NS):
        sys_ = ev.find("e:System", NS)
        if sys_ is None:
            continue
        log = sys_.findtext("e:Channel", default="", namespaces=NS)
        eid = int(sys_.findtext("e:EventID", default="0", namespaces=NS))
        tc = sys_.find("e:TimeCreated", NS)
        time = (tc.get("SystemTime", "") if tc is not None else "")[:19]
        data = {d.get("Name", f"Data{i}"): (d.text or "") for i, d in enumerate(ev.findall("e:EventData/e:Data", NS))}
        events.append(Event(log, eid, time, data))
    return events


# ------------------------------------------------------------------ hallazgos
def _exe_from_cmdline(cmdline: str) -> str:
    """Primer token de una línea de comandos (respetando comillas), con %VAR% expandidas."""
    cmd = expand_win_vars(cmdline.strip())
    if not cmd:
        return ""
    if cmd.startswith('"'):
        return cmd[1 : cmd.find('"', 1)] if cmd.count('"') >= 2 else cmd.strip('"')
    try:
        return shlex.split(cmd, posix=False)[0]
    except ValueError:
        return cmd.split()[0]


def _task_command(task_xml: str) -> tuple[str, str]:
    try:
        root = ET.fromstring(task_xml)
    except ET.ParseError:
        return "", ""
    exec_ = root.find(".//t:Actions/t:Exec", TASK_NS)
    if exec_ is None:
        return "", ""
    return (
        exec_.findtext("t:Command", default="", namespaces=TASK_NS),
        exec_.findtext("t:Arguments", default="", namespaces=TASK_NS),
    )


def event_to_finding(ev: Event) -> Finding | None:
    d = ev.data
    if ev.event_id == 7045:
        image = d.get("ImagePath", "")
        f = Finding(
            source="event",
            name=d.get("ServiceName", "?"),
            path=_exe_from_cmdline(image),
            publisher=d.get("AccountName", "") or "(desconocido)",
            signature="(no verificada)",
            sha256="",
            category="Servicio instalado (7045)",
            location=f"System · {ev.time}",
            cmdline=image,
            created=ev.time,
        )
        f.add(
            Signal(
                "EVT_SERVICE_INSTALLED", "Servicio instalado recientemente", 10, "T1543.003", d.get("ServiceName", "")
            )
        )
        return f
    if ev.event_id == 4698:
        command, args = _task_command(d.get("TaskContent", ""))
        f = Finding(
            source="event",
            name=d.get("TaskName", "?"),
            path=expand_win_vars(command),
            publisher=d.get("SubjectUserName", "") or "(desconocido)",
            signature="(no verificada)",
            sha256="",
            category="Tarea programada creada (4698)",
            location=f"Security · {ev.time}",
            cmdline=f"{command} {args}".strip(),
            created=ev.time,
        )
        f.add(
            Signal("EVT_TASK_CREATED", "Tarea programada creada recientemente", 10, "T1053.005", d.get("TaskName", ""))
        )
        return f
    if ev.event_id in (1116, 1117):
        raw = d.get("Path", "")
        m = re.search(r"file:_([^;]+)", raw)
        path = m.group(1) if m else raw.split(";")[0]
        action = "detección" if ev.event_id == 1116 else "acción tomada"
        f = Finding(
            source="event",
            name=d.get("Threat Name", "?"),
            path=path,
            publisher="Microsoft Defender",
            signature="(no verificada)",
            sha256="",
            category=f"Defender {ev.event_id} ({action})",
            location=f"Defender · {ev.time}",
            cmdline=d.get("Process Name", ""),
            created=ev.time,
        )
        f.add(
            Signal(
                "DEFENDER_DETECTION",
                "Microsoft Defender detectó una amenaza",
                80,
                "",
                f"{d.get('Threat Name', '?')} · {d.get('Severity Name', '')} · {d.get('Action Name', '')}".strip(" ·"),
            )
        )
        return f
    return None


def collect_events(days: int) -> tuple[list[Finding], list[str]]:
    """Devuelve (hallazgos, avisos de registros no disponibles)."""
    findings: list[Finding] = []
    warnings: list[str] = []
    for log, ids in LOGS:
        try:
            events = parse_events(query_log(log, ids, days))
        except (RuntimeError, OSError, subprocess.TimeoutExpired, ET.ParseError) as e:
            warnings.append(f"Eventos de «{log}» no disponibles: {e}")
            continue
        findings += [f for f in map(event_to_finding, events) if f]
    return findings, warnings
