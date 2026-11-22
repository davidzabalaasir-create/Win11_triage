import threading

import pytest

from win11_triage import env_check
from win11_triage.engine import Reporter, TriageEngine, TriageOptions
from win11_triage.models import Cancelled, Status


class Recorder(Reporter):
    def __init__(self):
        self.events = []

    def info(self, text):
        self.events.append(("info", text))

    def vt_start(self, total, cached, new, eta):
        self.events.append(("vt_start", total, cached, new))

    def vt_progress(self, index, total, sha256, result, origin):
        self.events.append(("vt_progress", index, origin))


def _tools():
    return {n: env_check.ToolStatus(n, None, "") for n in env_check.TOOLS}


def test_options_vt_implies_collectors(tmp_path):
    o = TriageOptions(vt=True, config_dir=tmp_path)
    assert o.autoruns and o.scan_user
    assert o.required_tools == {"autorunsc.exe", "sigcheck.exe"}
    assert TriageOptions(autoruns=True, dry_run=True, config_dir=tmp_path).required_tools == set()


def test_engine_dry_run_reports_progress(tmp_path):
    opts = TriageOptions(autoruns=True, scan_user=True, network=True, vt=True, dry_run=True, config_dir=tmp_path)
    rec = Recorder()
    res = TriageEngine(opts, _tools(), rec).run()
    assert res.modules == ["autoruns", "scan-user", "network", "vt"]
    assert res.counts()[Status.DETECTED] == 8
    assert ("vt_start", 10, 0, 10) in rec.events
    assert sum(1 for e in rec.events if e[0] == "vt_progress") == 10
    assert any(e[0] == "info" and "conexiones" in e[1] for e in rec.events)


def test_engine_honours_cancel(tmp_path):
    cancel = threading.Event()
    cancel.set()
    opts = TriageOptions(autoruns=True, dry_run=True, config_dir=tmp_path)
    with pytest.raises(Cancelled):
        TriageEngine(opts, _tools(), cancel=cancel).run()


def test_engine_skips_vt_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr("win11_triage.collectors.collect_autoruns", lambda exe: [])
    tools = _tools()
    tools["autorunsc.exe"] = env_check.ToolStatus("autorunsc.exe", tmp_path / "autorunsc.exe", "PATH")
    res = TriageEngine(TriageOptions(autoruns=True, vt=True, config_dir=tmp_path), tools).run()
    assert any("VT_API_KEY" in e for e in res.errors)
    assert res.vt_stats is None


def test_default_config_dir_for_installed_and_portable_app(tmp_path, monkeypatch):
    import sys

    from win11_triage import engine

    monkeypatch.delenv("WIN11_TRIAGE_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    exe_dir = tmp_path / "Program Files" / "win11-triage"
    exe_dir.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "win11-triage-gui.exe"))
    # Instalada: datos en %LOCALAPPDATA% (Archivos de programa no es escribible)
    assert engine.default_config_dir() == tmp_path / "local" / "win11-triage"
    # Portable: junto al .exe
    (exe_dir / "portable.txt").write_text("x")
    assert engine.default_config_dir() == exe_dir
    monkeypatch.setenv("WIN11_TRIAGE_HOME", str(tmp_path / "custom"))
    assert engine.default_config_dir() == (tmp_path / "custom").resolve()
