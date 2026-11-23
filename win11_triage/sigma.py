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
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
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
class _Event:
    """Evento preparado una sola vez: campos originales, en minúsculas y texto completo."""

    __slots__ = ("_blob", "low", "raw")

    def __init__(self, raw: dict[str, str]) -> None:
        self.raw = raw
        self.low = {k: v.lower() for k, v in raw.items()}
        self._blob: str | None = None

    @property
    def blob(self) -> str:
        if self._blob is None:
            self._blob = " ".join(self.low.values())
        return self._blob


@lru_cache(maxsize=4096)
def _split_key(key: str) -> tuple[str, frozenset[str]]:
    name, *mods = key.split("|")
    return name, frozenset(mods)


@lru_cache(maxsize=4096)
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# ------------------------------------------------------------------ compilación
# Cada regla se compila una vez a funciones: los valores esperados ya van en minúsculas, los
# modificadores resueltos y la condición convertida en un árbol. Evaluar un evento es entonces
# llamar a esas funciones, sin volver a interpretar la regla.
Pred = Callable[[_Event], bool]
_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*]+", re.IGNORECASE)


def _compile_value(expected: Any, mods: frozenset[str]) -> Callable[[str, str], bool]:
    if expected is None:
        return lambda actual, _a: actual == ""
    exp = str(expected)
    if "re" in mods:
        rx = _regex(exp)
        return lambda actual, _a: rx.search(actual) is not None
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(exp, strict=False)
        except ValueError:
            return lambda _x, _a: False

        def in_net(actual: str, _a: str) -> bool:
            try:
                return ipaddress.ip_address(actual) in net
            except ValueError:
                return False

        return in_net
    e = exp.lower()
    if "contains" in mods:
        return lambda _x, a: e in a
    if "startswith" in mods:
        return lambda _x, a: a.startswith(e)
    if "endswith" in mods:
        return lambda _x, a: a.endswith(e)
    if "*" in e or "?" in e:
        rx = re.compile(fnmatch.translate(e), re.S)
        return lambda _x, a: rx.match(a) is not None
    return lambda _x, a: a == e


def _compile_field(key: str, expected: Any) -> Pred:
    name, mods = _split_key(key)
    checks = [_compile_value(v, mods) for v in (expected if isinstance(expected, list) else [expected])]
    combine = all if "all" in mods else any

    def field(ev: _Event) -> bool:
        actual = ev.raw.get(name)
        if actual is None:
            return False
        low = ev.low[name]
        return combine(c(actual, low) for c in checks)

    return field


def _compile_selection(sel: Any) -> Pred:
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            parts = [_compile_selection(x) for x in sel]
            return lambda ev: any(p(ev) for p in parts)
        words = [str(x).lower() for x in sel]  # palabras clave en cualquier campo
        return lambda ev: any(w in ev.blob for w in words)
    if isinstance(sel, dict):
        fields = [_compile_field(k, v) for k, v in sel.items()]
        return lambda ev: all(f(ev) for f in fields)
    return lambda _ev: False


@lru_cache(maxsize=1024)
def _tokens(text: str) -> tuple[str, ...]:
    return tuple(t.lower() if t.lower() in ("and", "or", "not", "1 of", "all of") else t for t in _TOKEN.findall(text))


class _Parser:
    """Convierte la condición en un predicado (precedencia: not > and > or)."""

    def __init__(self, text: str, sels: dict[str, Pred]) -> None:
        self.tokens, self.i, self.sels = _tokens(text), 0, sels

    def _peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _take(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Pred:
        return self._or()

    def _or(self) -> Pred:
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda ev: any(p(ev) for p in parts))

    def _and(self) -> Pred:
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda ev: all(p(ev) for p in parts))

    def _not(self) -> Pred:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda ev: not inner(ev)
        return self._atom()

    def _atom(self) -> Pred:
        tok = self._take()
        if tok == "(":
            inner = self._or()
            if self._peek() == ")":
                self._take()
            return inner
        if tok in ("1 of", "all of"):
            pattern = self._take()
            names = list(self.sels) if pattern == "them" else [n for n in self.sels if fnmatch.fnmatchcase(n, pattern)]
            preds = [self.sels[n] for n in names]
            if tok == "1 of":
                return lambda ev: any(p(ev) for p in preds)
            return lambda ev: bool(preds) and all(p(ev) for p in preds)
        return self.sels.get(tok, lambda _ev: False)


def compile_detection(detection: dict[str, Any]) -> Pred:
    sels = {k: _compile_selection(v) for k, v in detection.items() if k != "condition"}
    conditions = detection.get("condition", "")
    conditions = [c for c in (conditions if isinstance(conditions, list) else [conditions]) if c]
    preds = [_Parser(c, sels).parse() for c in conditions]
    return lambda ev: any(p(ev) for p in preds)


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
    _predicate: Pred | None = field(default=None, repr=False, compare=False)

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

    @property
    def predicate(self) -> Pred:
        if self._predicate is None:
            self._predicate = compile_detection(self.detection)
        return self._predicate

    def matches(self, ev: Event, prepared: _Event | None = None) -> bool:
        if prepared is None:
            if not self.applies_to(ev):
                return False
            prepared = _Event(normalize(ev))
        return self.predicate(prepared)


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
    applicable: dict[tuple[str, int], list[SigmaRule]] = {}  # (registro, id) → reglas que aplican
    for ev in events:
        sig = (ev.log, ev.event_id)
        if sig not in applicable:
            applicable[sig] = [r for r in rules if r.applies_to(ev)]
        if not applicable[sig]:
            continue
        data = normalize(ev)
        prepared = _Event(data)
        for rule in applicable[sig]:
            if not rule.matches(ev, prepared):
                continue
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
