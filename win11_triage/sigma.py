"""Motor Sigma ligero para eventos de Windows (Sysmon, Security 4688, PowerShell 4104, System 7045).

Soporta el subconjunto de Sigma que usan la mayoría de reglas de endpoint:
- ``logsource``: ``product: windows`` con ``category`` (process_creation, network_connection,
  file_event, registry_set/registry_event, dns_query, ps_script) o ``service`` (system, security,
  sysmon, powershell).
- Selecciones: mapas (AND entre campos, OR entre valores de una lista) o listas de mapas (OR).
- Modificadores: ``contains``, ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``; comodines ``*`` ``?``.
- Condiciones: ``and``, ``or``, ``not``, paréntesis, ``1 of sel*``, ``all of sel*``, ``1 of them``.

Reglas incluidas en ``rules/sigma/`` y reglas propias en ``<config-dir>/sigma/*.yml``.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .collectors_events import Event
from .i18n import get_language
from .models import Finding, Signal

BUILTIN_DIR = Path(__file__).resolve().parent / "rules" / "sigma"
LEVEL_WEIGHT = {"informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 85}

# ------------------------------------------------------------------ eventos → categoría Sigma
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSMON_CATEGORY = {1: "process_creation", 3: "network_connection", 11: "file_event", 12: "registry_event",
                   13: "registry_set", 14: "registry_event", 22: "dns_query"}  # fmt: skip


def event_category(ev: Event) -> str:
    if ev.log == SYSMON:
        return SYSMON_CATEGORY.get(ev.event_id, "")
    if ev.log == "Security" and ev.event_id == 4688:
        return "process_creation"
    if ev.log.startswith("Microsoft-Windows-PowerShell") and ev.event_id == 4104:
        return "ps_script"
    return ""


def event_service(ev: Event) -> str:
    if ev.log == SYSMON:
        return "sysmon"
    if ev.log.startswith("Microsoft-Windows-PowerShell"):
        return "powershell"
    return ev.log.lower()  # system, security…


def normalize(ev: Event) -> dict[str, str]:
    """Campos del evento con los nombres que usa Sigma (Security 4688 → nombres de Sysmon)."""
    d = dict(ev.data)
    d["EventID"] = str(ev.event_id)
    if ev.log == "Security" and ev.event_id == 4688:
        d.setdefault("Image", d.get("NewProcessName", ""))
        d.setdefault("ParentImage", d.get("ParentProcessName", ""))
    if "Image" in d:
        d.setdefault("OriginalFileName", "")
    return d


# ------------------------------------------------------------------ coincidencia de valores
def _value_match(actual: str, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return actual == ""
    exp = str(expected)
    if "re" in mods:
        return re.search(exp, actual, re.IGNORECASE) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(exp, strict=False)
        except ValueError:
            return False
    a, e = actual.lower(), exp.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _field_match(event: dict[str, str], key: str, expected: Any) -> bool:
    name, *mods = key.split("|")
    actual = event.get(name)
    if actual is None:
        return False
    values = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(_value_match(actual, v, mods) for v in values)
    return any(_value_match(actual, v, mods) for v in values)


def _selection_match(event: dict[str, str], sel: Any) -> bool:
    if isinstance(sel, list):  # lista de mapas → OR; lista de cadenas → palabra clave en cualquier campo
        if all(isinstance(x, dict) for x in sel):
            return any(_selection_match(event, x) for x in sel)
        blob = " ".join(event.values()).lower()
        return any(str(x).lower() in blob for x in sel)
    if isinstance(sel, dict):
        return all(_field_match(event, k, v) for k, v in sel.items())
    return False


# ------------------------------------------------------------------ condiciones
_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*]+", re.IGNORECASE)


class _Cond:
    def __init__(self, text: str, sels: dict[str, Any], event: dict[str, str]) -> None:
        self.tokens = [
            t.lower() if t.lower() in ("and", "or", "not", "1 of", "all of") else t for t in _TOKEN.findall(text)
        ]
        self.i, self.sels, self.event = 0, sels, event

    def _peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _take(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        val = self._and()
        while self._peek() == "or":
            self._take()
            val = self._and() or val
        return val

    def _and(self) -> bool:
        val = self._not()
        while self._peek() == "and":
            self._take()
            rhs = self._not()
            val = val and rhs
        return val

    def _not(self) -> bool:
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._take()
        if tok == "(":
            val = self._or()
            if self._peek() == ")":
                self._take()
            return val
        if tok in ("1 of", "all of"):
            pattern = self._take()
            names = list(self.sels) if pattern == "them" else [n for n in self.sels if fnmatch.fnmatchcase(n, pattern)]
            results = [_selection_match(self.event, self.sels[n]) for n in names]
            return any(results) if tok == "1 of" else bool(results) and all(results)
        return _selection_match(self.event, self.sels.get(tok))


# ------------------------------------------------------------------ reglas
@dataclass
class SigmaRule:
    title: str
    id: str
    level: str
    tags: list[str]
    logsource: dict[str, str]
    detection: dict[str, Any]
    description: str = ""
    source: str = ""
    falsepositives: list[str] = field(default_factory=list)

    @property
    def attack(self) -> str:
        ids = [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t, re.I)]
        return ", ".join(ids)

    def applies_to(self, ev: Event) -> bool:
        ls = self.logsource
        if ls.get("product", "windows").lower() != "windows":
            return False
        cat = ls.get("category")
        if cat:
            evcat = event_category(ev)
            return evcat == cat or (cat == "registry_event" and evcat == "registry_set")
        svc = ls.get("service")
        return bool(svc) and svc.lower() == event_service(ev)

    def matches(self, ev: Event) -> bool:
        if not self.applies_to(ev):
            return False
        sels = {k: v for k, v in self.detection.items() if k != "condition"}
        conditions = self.detection.get("condition", "")
        conditions = conditions if isinstance(conditions, list) else [conditions]
        event = normalize(ev)
        return any(_Cond(c, sels, event).parse() for c in conditions if c)


def load_rules(extra_dir: Path | None = None) -> tuple[list[SigmaRule], list[str]]:
    """Devuelve (reglas, avisos de reglas que no se pudieron cargar)."""
    rules, warnings = [], []
    paths = sorted(BUILTIN_DIR.glob("*.yml"))
    if extra_dir and extra_dir.is_dir():
        paths += sorted(extra_dir.glob("*.yml")) + sorted(extra_dir.glob("*.yaml"))
    for p in paths:
        try:
            for doc in yaml.safe_load_all(p.read_text(encoding="utf-8")):
                if not isinstance(doc, dict) or "detection" not in doc:
                    continue
                rules.append(
                    SigmaRule(
                        title=str(
                            doc.get("title_en")
                            if get_language() == "en" and doc.get("title_en")
                            else doc.get("title", p.stem)
                        ),
                        id=str(doc.get("id", p.stem)),
                        level=str(doc.get("level", "medium")).lower(),
                        tags=[str(t) for t in doc.get("tags", [])],
                        logsource=dict(doc.get("logsource", {})),
                        detection=dict(doc["detection"]),
                        description=str(doc.get("description", "")),
                        source=p.name,
                        falsepositives=[str(x) for x in doc.get("falsepositives", [])],
                    )
                )
        except (OSError, yaml.YAMLError, TypeError, ValueError) as e:
            warnings.append(f"Regla Sigma {p.name} ignorada: {e}")
    return rules, warnings


# ------------------------------------------------------------------ hallazgos
def _subject(ev: dict[str, str]) -> tuple[str, str]:
    """(ruta principal, línea de comandos) del evento para el hallazgo."""
    path = (
        ev.get("Image")
        or ev.get("TargetFilename")
        or ev.get("TargetObject")
        or ev.get("ImagePath")
        or ev.get("Path", "")
    )
    cmd = (
        ev.get("CommandLine")
        or ev.get("ScriptBlockText", "")[:400]
        or ev.get("Details")
        or ev.get("QueryName")
        or ev.get("ImagePath", "")
    )
    if ev.get("DestinationIp"):
        cmd = f"{cmd} → {ev['DestinationIp']}:{ev.get('DestinationPort', '')}".strip()
    return path, cmd


def scan_events(events: list[Event], rules: list[SigmaRule]) -> list[Finding]:
    """Aplica las reglas y agrupa coincidencias iguales (misma regla, imagen y línea de comandos)."""
    groups: dict[tuple[str, str, str], tuple[Finding, int]] = {}
    for ev in events:
        for rule in rules:
            if not rule.matches(ev):
                continue
            data = normalize(ev)
            path, cmd = _subject(data)
            key = (rule.id, path.lower(), cmd.lower())
            if key in groups:
                f, n = groups[key]
                groups[key] = (f, n + 1)
                continue
            f = Finding(
                source="sigma",
                name=rule.title,
                path=path,
                publisher=data.get("User", "") or "(desconocido)",
                signature="(no verificada)",
                sha256=_sha256_from_hashes(data.get("Hashes", "")),
                category=f"Sigma · {rule.logsource.get('category') or rule.logsource.get('service', '')}",
                location=f"{ev.log} {ev.event_id} · {ev.time}",
                cmdline=cmd,
                created=ev.time,
                parent=(data.get("ParentImage", "").rsplit("\\", 1)[-1]).lower(),
            )
            f.add(
                Signal(
                    f"SIGMA_{rule.id[:36]}",
                    f"Sigma: {rule.title}",
                    LEVEL_WEIGHT.get(rule.level, 35),
                    rule.attack,
                    f"{rule.level} · {rule.source}",
                )
            )
            groups[key] = (f, 1)
    findings = []
    for f, n in groups.values():
        if n > 1:
            f.location += f" · {n} veces"
        findings.append(f)
    return findings


def _sha256_from_hashes(hashes: str) -> str:
    """Sysmon: 'SHA1=…,MD5=…,SHA256=…,IMPHASH=…'."""
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes or "")
    return m.group(1).lower() if m else ""
