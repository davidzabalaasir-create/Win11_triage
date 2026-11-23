"""Motor de triaje compartido por la CLI y la interfaz gráfica.

No escribe en pantalla: comunica el progreso a través de un :class:`Reporter`,
que cada interfaz implementa a su manera (Rich en la terminal, cola de eventos en la GUI).

Flujo: colectores → lista blanca → reglas → red → contenido (PE/YARA) → VirusTotal → veredicto.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import collectors, collectors_browsers, collectors_events, collectors_live, env_check, intel, sigma
from .enrich import eligible, file_of, pe_static, yara_scan
from .models import Cancelled, Finding, Signal
from .report import TriageResult
from .rules import apply_rules, apply_vt
from .virustotal import FREE_TIER_INTERVAL, VTAuthError, VTClient, VTResult
from .whitelist import Whitelist

SAMPLES = Path(__file__).resolve().parent / "samples"
PLACEHOLDER_KEY = "pon_aqui_tu_api_key"

SECTION_AUTORUNS = "Persistencia (Autoruns)"
SECTION_SIGCHECK = "Carpetas de usuario (Sigcheck) — sin firma válida"
SECTION_PROCESSES = "Procesos en ejecución — sospechosos"
SECTION_EVENTS = "Eventos de Windows — servicios, tareas y Defender"
SECTION_SIGMA = "Reglas Sigma — Sysmon, 4688, PowerShell"
SECTION_BROWSERS = "Extensiones de navegador"


APP_NAME = "win11-triage"


def user_data_dir() -> Path:
    """%LOCALAPPDATA%\\win11-triage (o ~/.win11-triage fuera de Windows)."""
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / APP_NAME if base else Path.home() / f".{APP_NAME}"


def default_config_dir() -> Path:
    """Dónde viven .env, whitelist.json, la caché y los informes.

    1. ``WIN11_TRIAGE_HOME`` si está definida.
    2. Aplicación instalada (.exe): ``%LOCALAPPDATA%\\win11-triage``, porque «Archivos de programa»
       no es escribible. Modo portable: si junto al .exe hay un ``portable.txt`` o un ``.env``,
       se usa la carpeta del .exe.
    3. Desde el código: la carpeta actual.
    """
    if os.environ.get("WIN11_TRIAGE_HOME"):
        return Path(os.environ["WIN11_TRIAGE_HOME"]).resolve()
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / "portable.txt").exists() or (exe_dir / ".env").exists():
            return exe_dir
        return user_data_dir()
    return Path.cwd().resolve()


@dataclass
class TriageOptions:
    autoruns: bool = False
    scan_user: bool = False
    processes: bool = False
    events: bool = False
    sigma: bool = False
    browsers: bool = False
    network: bool = False
    static: bool = False
    vt: bool = False
    intel: bool = False
    dry_run: bool = False
    vt_limit: int | None = None
    event_days: int = 7
    config_dir: Path | None = None

    def __post_init__(self) -> None:
        self.config_dir = (self.config_dir or default_config_dir()).resolve()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if (self.vt or self.network or self.static or self.intel) and not self.any_collector:
            self.autoruns = self.scan_user = True  # necesitan hallazgos de los que partir

    @property
    def any_collector(self) -> bool:
        return self.autoruns or self.scan_user or self.processes or self.events or self.sigma or self.browsers

    @property
    def required_tools(self) -> set[str]:
        if self.dry_run:
            return set()
        return {n for n, on in (("autorunsc.exe", self.autoruns), ("sigcheck.exe", self.scan_user)) if on}

    @property
    def whitelist_file(self) -> Path:
        return SAMPLES / "whitelist_sample.json" if self.dry_run else self.config_dir / "whitelist.json"  # type: ignore[operator]


class Reporter:
    """Receptor de eventos de progreso. Las implementaciones sobrescriben lo que necesiten."""

    def stage(self, text: str) -> None:
        """Empieza una fase larga (indeterminada)."""

    def done(self) -> None:
        """Termina la fase en curso."""

    def info(self, text: str) -> None: ...

    def warn(self, text: str) -> None: ...

    def error(self, text: str) -> None: ...

    def vt_start(self, total: int, cached: int, new: int, eta: float) -> None: ...

    def vt_progress(self, index: int, total: int, sha256: str, result: VTResult, origin: str) -> None: ...

    def vt_wait(self, remaining: float) -> None: ...


# ----------------------------------------------------------------- dry-run
def sample_text(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def _sample_json(name: str) -> dict[str, Any]:
    return json.loads(sample_text(name))


def _dry_vt_simulator() -> Callable[[str], VTResult]:
    data = _sample_json("vt_responses.json")
    return lambda h: dict(data.get(h, {"found": False}))


def share_hashes(findings: list[Finding]) -> None:
    """Propaga el SHA-256 entre hallazgos que apuntan al mismo fichero (proceso/evento ← autoruns/sigcheck)."""
    known = {f.path.strip().strip('"').lower(): f.sha256 for f in findings if f.sha256 and f.path}
    for f in findings:
        if not f.sha256 and f.path:
            f.sha256 = known.get(f.path.strip().strip('"').lower(), "")


# ----------------------------------------------------------------- motor
class TriageEngine:
    def __init__(
        self,
        opts: TriageOptions,
        tools: dict[str, env_check.ToolStatus],
        reporter: Reporter | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.opts = opts
        self.tools = tools
        self.r = reporter or Reporter()
        self.cancel = cancel or threading.Event()
        self._procs: dict[int, collectors_live.ProcInfo] | None = None
        self._conns: list | None = None

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise Cancelled

    def run(self) -> TriageResult:
        """Ejecuta los módulos activos. Puede lanzar WhitelistError o Cancelled."""
        whitelist = Whitelist.load(self.opts.whitelist_file, create=not self.opts.dry_run)
        res = TriageResult(
            host=platform.node() or "host",
            user=getpass.getuser(),
            started=datetime.now(),
            dry_run=self.opts.dry_run,
            admin=env_check.is_admin(),
            tools=self.tools,
        )
        plan = (
            ("autoruns", self.opts.autoruns, SECTION_AUTORUNS, self._autoruns),
            ("scan-user", self.opts.scan_user, SECTION_SIGCHECK, self._sigcheck),
            ("processes", self.opts.processes, SECTION_PROCESSES, self._processes),
            ("events", self.opts.events, SECTION_EVENTS, self._events),
            ("sigma", self.opts.sigma, SECTION_SIGMA, self._sigma),
            ("browsers", self.opts.browsers, SECTION_BROWSERS, self._browsers),
        )
        for module, enabled, section, fn in plan:
            if not enabled:
                continue
            self._check_cancel()
            res.modules.append(module)
            try:
                found = fn(res)
            except collectors.CollectorError as e:
                self._fail(res, str(e))
                found = []
            finally:
                self.r.done()
            found, skipped = whitelist.filter(found)
            res.whitelisted += skipped
            res.sections[section] = found

        apply_rules(res.findings)

        if self.opts.network:
            self._check_cancel()
            res.modules.append("network")
            self._network(res)
        if self.opts.static:
            self._check_cancel()
            res.modules.append("static")
            self._static(res)
        share_hashes(res.findings)
        if self.opts.vt:
            self._check_cancel()
            res.modules.append("vt")
            self._vt(res)
        apply_vt(res.findings)
        if self.opts.intel:
            self._check_cancel()
            res.modules.append("intel")
            self._intel(res)
        if self._procs is not None:
            self._record_process_tree(res)
        res.finished = datetime.now()
        return res

    def _fail(self, res: TriageResult, msg: str) -> None:
        res.errors.append(msg)
        self.r.error(msg)

    # --------------------------------------------------------- colectores
    def _autoruns(self, res: TriageResult) -> list[Finding]:
        if self.opts.dry_run:
            raw = sample_text("autorunsc_sample.csv").encode("utf-16")  # mismo decodificador que el real
            return collectors.parse_autoruns(collectors.decode_output(raw))
        self.r.stage("Ejecutando autorunsc (puede tardar varios minutos)…")
        return collectors.collect_autoruns(self.tools["autorunsc.exe"].path)  # type: ignore[arg-type]

    def _sigcheck(self, res: TriageResult) -> list[Finding]:
        if self.opts.dry_run:
            return collectors.parse_sigcheck(sample_text("sigcheck_sample.csv"), "(muestra)")
        found: list[Finding] = []
        for folder in collectors.user_scan_targets():
            self._check_cancel()
            if not folder.is_dir():
                continue
            self.r.stage(f"Ejecutando sigcheck sobre {folder}…")
            try:
                found += collectors.collect_sigcheck(self.tools["sigcheck.exe"].path, folder)  # type: ignore[arg-type]
            except collectors.CollectorError as e:
                self._fail(res, str(e))
        return found

    def _snapshot(self) -> tuple[dict[int, collectors_live.ProcInfo], list]:
        """Procesos y conexiones (una sola captura compartida por --processes y --network)."""
        if self._procs is None:
            if self.opts.dry_run:
                self._procs, self._conns = collectors_live.parse_sample(_sample_json("processes_sample.json"))
            else:
                self.r.stage("Capturando procesos y conexiones…")
                self._procs = collectors_live.snapshot_processes()
                self._conns = collectors_live.snapshot_connections(self._procs)
        return self._procs, self._conns or []

    def _record_process_tree(self, res: TriageResult) -> None:
        """Guarda el árbol de procesos con los señalados marcados (para la vista de árbol y los informes)."""
        scores: dict[int, int] = {}
        for f in res.findings:
            if f.pid is not None:
                scores[f.pid] = max(scores.get(f.pid, 0), f.score)
        res.processes = [
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "exe": p.exe,
                "cmdline": p.cmdline[:500],
                "created": p.created,
                "flagged": p.pid in scores,
                "score": scores.get(p.pid, 0),
            }
            for p in (self._procs or {}).values()
        ]

    def _processes(self, res: TriageResult) -> list[Finding]:
        if not collectors_live.available():
            self._fail(res, "psutil no está instalado: se omite el análisis de procesos")
            return []
        procs, _ = self._snapshot()
        found = collectors_live.process_findings(procs, compute_hashes=not self.opts.dry_run)
        self.r.info(f"Procesos: {len(procs)} en ejecución · {len(found)} con indicios sospechosos.")
        return found

    def _events(self, res: TriageResult) -> list[Finding]:
        if self.opts.dry_run:
            events = collectors_events.parse_events(sample_text("events_sample.xml"))
            found = [f for f in map(collectors_events.event_to_finding, events) if f]
        else:
            self.r.stage(f"Leyendo eventos de los últimos {self.opts.event_days} días…")
            found, warnings = collectors_events.collect_events(self.opts.event_days)
            for w in warnings:
                res.errors.append(w)
                self.r.warn(w)
        self.r.info(f"Eventos: {len(found)} relevantes (servicios, tareas, Defender).")
        return found

    def _sigma(self, res: TriageResult) -> list[Finding]:
        self.r.stage("Aplicando reglas Sigma a los eventos…")
        rules, warnings = sigma.load_rules(self.opts.config_dir / "sigma")  # type: ignore[operator]
        if self.opts.dry_run:
            events = collectors_events.parse_events(sample_text("sysmon_sample.xml"))
            have_sysmon = True
        else:
            events, more, have_sysmon = collectors_events.collect_raw_events(self.opts.event_days)
            warnings += more
        for w in warnings:
            res.errors.append(w)
            self.r.warn(w)
        found = sigma.scan_events(events, rules)
        src = "Sysmon + Windows" if have_sysmon else "Windows (sin Sysmon)"
        self.r.info(f"Sigma: {len(rules)} reglas sobre {len(events)} eventos ({src}) → {len(found)} coincidencias.")
        return found

    def _browsers(self, res: TriageResult) -> list[Finding]:
        self.r.stage("Revisando extensiones de Chrome, Edge, Brave y Firefox…")
        if self.opts.dry_run:
            exts = _sample_json("browsers_sample.json")["extensions"]
        else:
            exts = collectors_browsers.collect_extensions()
        found = collectors_browsers.extension_findings(exts)
        self.r.info(f"Navegadores: {len(exts)} extensiones · {len(found)} con permisos u origen a revisar.")
        return found

    # --------------------------------------------------------- red
    def _network(self, res: TriageResult) -> None:
        if collectors_live.available():
            try:
                procs, conns = self._snapshot()
            except Exception as e:
                self.r.warn(f"psutil no pudo leer las conexiones ({e}); se usa tcpvcon.")
            else:
                res.connections = conns
                matched = collectors_live.attach_connections(res.findings, conns, procs)
                self.r.info(f"Red: {len(conns)} conexiones externas · {matched} hallazgo(s) con conexiones (por PID).")
                return
        self._network_tcpvcon(res)

    def _network_tcpvcon(self, res: TriageResult) -> None:
        exe = self.tools["tcpvcon.exe"].path
        if exe is None:
            self._fail(res, "Ni psutil ni tcpvcon disponibles: se omite el módulo de red")
            return
        self.r.stage("Ejecutando tcpvcon…")
        try:
            conns = collectors.collect_tcpvcon(exe)
        except collectors.CollectorError as e:
            self._fail(res, str(e))
            return
        finally:
            self.r.done()
        res.connections = conns
        matched = collectors.correlate_connections(res.findings, conns)
        for f in res.findings:
            if f.connections:
                f.signals.append(
                    Signal("NET_ACTIVE", "Conexiones de red activas", 10, "T1071", f.connections[0].remote)
                )
        self.r.info(f"Red: {len(conns)} conexiones · {matched} hallazgo(s) con conexiones (por nombre, tcpvcon).")

    # --------------------------------------------------------- contenido
    def _static(self, res: TriageResult) -> None:
        targets = [f for f in res.findings if eligible(f)]
        if self.opts.dry_run:
            sim = _sample_json("content_sample.json")
            for f in targets:
                key = f.path.strip().strip('"').lower()
                f.signals += [Signal(**d) for d in sim["static"].get(key, [])]
                f.signals += [yara_scan.match_to_signal(m["rule"], m["meta"]) for m in sim["yara"].get(key, [])]
            self.r.info(f"Contenido: {len(targets)} elemento(s) analizados (simulado).")
            return

        scanner = None
        if yara_scan.available():
            try:
                scanner = yara_scan.YaraScanner(self.opts.config_dir / "yara")  # type: ignore[operator]
            except Exception as e:
                self._fail(res, f"YARA: no se pudieron compilar las reglas ({e})")
        else:
            self.r.warn('YARA no disponible (pip install "win11-triage[yara]"): solo análisis PE.')
        seen: dict[Path, list[Signal]] = {}
        analysed = 0
        for i, f in enumerate(targets, 1):
            self._check_cancel()
            path = file_of(f)
            if path is None:
                continue
            if path not in seen:
                self.r.stage(f"Analizando contenido {i}/{len(targets)}: {path.name}")
                sigs = pe_static.pe_signals(path)
                if scanner is not None:
                    sigs += scanner.scan(path)
                seen[path] = sigs
                analysed += 1
            f.signals += seen[path]
        self.r.done()
        self.r.info(f"Contenido: {analysed} fichero(s) analizados (PE{' + YARA' if scanner else ''}).")

    # --------------------------------------------------------- reputación
    def _intel(self, res: TriageResult) -> None:
        self.r.stage("Consultando reputación (AbuseIPDB, MalwareBazaar)…")
        if self.opts.dry_run:
            known = {h for h, v in _sample_json("vt_responses.json").items() if isinstance(v, dict) and v.get("label")}
            ip_lookup, hash_lookup = intel.demo_ip_lookup, intel.demo_hash_lookup(known)
        else:
            abuse = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
            mb = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
            ip_lookup = intel.abuseipdb_lookup(abuse) if abuse else None
            hash_lookup = intel.malwarebazaar_lookup(mb) if mb else None
            if not (abuse or mb):
                msg = "Ni ABUSEIPDB_API_KEY ni MALWAREBAZAAR_API_KEY configuradas: se omite la reputación."
                res.errors.append(msg)
                self.r.warn(msg)
                return
        cache = intel.IntelCache(self.opts.config_dir / "intel_cache.json", persist=not self.opts.dry_run)  # type: ignore[operator]
        stats = intel.enrich(res.findings, ip_lookup, hash_lookup, cache, on_warn=self.r.warn)
        res.intel_stats = stats
        self.r.done()
        self.r.info(
            f"Reputación: {stats['ips']} IP ({stats['ip_bad']} maliciosas) · {stats['hashes']} hashes "
            f"({stats['hash_known']} conocidos en MalwareBazaar) · {stats['cache']} desde caché."
        )

    # --------------------------------------------------------- VirusTotal
    def _vt(self, res: TriageResult) -> None:
        api_key = os.environ.get("VT_API_KEY", "").strip()
        if not self.opts.dry_run and api_key in ("", PLACEHOLDER_KEY):
            msg = "VT_API_KEY no configurada: se omite VirusTotal."
            res.errors.append(msg)
            self.r.warn(msg)
            return

        client = VTClient(
            api_key=api_key or "dry-run",
            cache_file=self.opts.config_dir / "vt_cache.json",  # type: ignore[operator]
            interval=0 if self.opts.dry_run else FREE_TIER_INTERVAL,
            simulator=_dry_vt_simulator() if self.opts.dry_run else None,
            persist=not self.opts.dry_run,
            on_wait=self.r.vt_wait,
            on_notice=self.r.warn,
            cancel=self.cancel,
        )
        hashes = sorted({f.sha256 for f in res.findings if f.sha256})
        pending = {h for h in hashes if not client.cached(h)}
        limit = len(pending) if self.opts.vt_limit is None else min(self.opts.vt_limit, len(pending))
        self.r.vt_start(len(hashes), len(hashes) - len(pending), limit, max(0, limit - 1) * client.interval)

        results: dict[str, VTResult] = {}
        new_queries = 0
        try:
            for i, h in enumerate(hashes, 1):
                if h in pending:
                    if new_queries >= limit:
                        client.stats["skipped"] += 1
                        continue
                    new_queries += 1
                r = client.lookup(h)
                results[h] = r
                origin = "caché" if r.get("cached") else ("simulado" if self.opts.dry_run else "API")
                self.r.vt_progress(i, len(hashes), h, r, origin)
        except VTAuthError as e:
            self._fail(res, f"VirusTotal: {e}")
        finally:
            self.r.done()
            client.save()
            for f in res.findings:
                f.vt = results.get(f.sha256, f.vt)
            res.vt_stats = client.stats
