"""Motor de triaje compartido por la CLI y la interfaz gráfica.

No escribe en pantalla: comunica el progreso a través de un :class:`Reporter`,
que cada interfaz implementa a su manera (Rich en la terminal, cola de eventos en la GUI).
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

from . import collectors, env_check
from .models import Cancelled, Finding
from .report import TriageResult
from .virustotal import FREE_TIER_INTERVAL, VTAuthError, VTClient, VTResult
from .whitelist import Whitelist

SAMPLES = Path(__file__).resolve().parent / "samples"
PLACEHOLDER_KEY = "pon_aqui_tu_api_key"

SECTION_AUTORUNS = "Persistencia (Autoruns) — no Microsoft / no verificado"
SECTION_SIGCHECK = "Rutas de usuario (Sigcheck) — sin firma válida"


def default_config_dir() -> Path:
    """WIN11_TRIAGE_HOME > carpeta del .exe (PyInstaller) > carpeta actual."""
    if os.environ.get("WIN11_TRIAGE_HOME"):
        return Path(os.environ["WIN11_TRIAGE_HOME"]).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd().resolve()


@dataclass
class TriageOptions:
    autoruns: bool = False
    scan_user: bool = False
    network: bool = False
    vt: bool = False
    dry_run: bool = False
    vt_limit: int | None = None
    config_dir: Path | None = None

    def __post_init__(self) -> None:
        self.config_dir = (self.config_dir or default_config_dir()).resolve()
        if (self.vt or self.network) and not (self.autoruns or self.scan_user):
            self.autoruns = self.scan_user = True  # VT y red necesitan hallazgos de los que partir

    @property
    def any_collector(self) -> bool:
        return self.autoruns or self.scan_user

    @property
    def required_tools(self) -> set[str]:
        if self.dry_run:
            return set()
        return {n for n, on in (("autorunsc.exe", self.autoruns), ("sigcheck.exe", self.scan_user)) if on}

    @property
    def whitelist_file(self) -> Path:
        return SAMPLES / "whitelist_sample.json" if self.dry_run else self.config_dir / "whitelist.json"


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


def _dry_autoruns() -> list[Finding]:
    # Se pasa por UTF-16 para ejercitar el mismo decodificador que con autorunsc real.
    return collectors.parse_autoruns(collectors.decode_output(sample_text("autorunsc_sample.csv").encode("utf-16")))


def _dry_sigcheck() -> list[Finding]:
    return collectors.parse_sigcheck(sample_text("sigcheck_sample.csv"), "(muestra)")


def _dry_vt_simulator() -> Callable[[str], VTResult]:
    data = json.loads(sample_text("vt_responses.json"))
    return lambda h: dict(data.get(h, {"found": False}))


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

        if self.opts.network:
            self._check_cancel()
            res.modules.append("network")
            self._network(res)
        if self.opts.vt:
            self._check_cancel()
            res.modules.append("vt")
            self._vt(res)
        res.finished = datetime.now()
        return res

    def _fail(self, res: TriageResult, msg: str) -> None:
        res.errors.append(msg)
        self.r.error(msg)

    # --------------------------------------------------------- módulos
    def _autoruns(self, res: TriageResult) -> list[Finding]:
        if self.opts.dry_run:
            return _dry_autoruns()
        self.r.stage("Ejecutando autorunsc (puede tardar varios minutos)…")
        return collectors.collect_autoruns(self.tools["autorunsc.exe"].path)  # type: ignore[arg-type]

    def _sigcheck(self, res: TriageResult) -> list[Finding]:
        if self.opts.dry_run:
            return _dry_sigcheck()
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

    def _network(self, res: TriageResult) -> None:
        if self.opts.dry_run:
            conns = collectors.parse_tcpvcon(sample_text("tcpvcon_sample.csv"))
        else:
            exe = self.tools["tcpvcon.exe"].path
            if exe is None:
                self._fail(res, "tcpvcon.exe no encontrado: se omite el módulo de red")
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
        self.r.info(f"Red: {len(conns)} conexiones activas · {matched} hallazgo(s) con conexiones.")

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
