"""Triaje remoto por WinRM: comando, parseo del JSON y motor en dry-run."""

import json

import pytest

from win11_triage import cli, remote
from win11_triage.engine import SAMPLES, TriageEngine, TriageOptions


def test_build_command_validates_input():
    cmd = remote.build_command("pc-01.corp.local")
    ps = cmd[-1]
    assert "Invoke-Command -ComputerName 'pc-01.corp.local'" in ps and str(remote.SCRIPT) in ps
    assert "-Credential" not in ps
    assert "Get-Credential -UserName 'CORP\\ana'" in remote.build_command("pc", "CORP\\ana", use_ssl=True)[-1]
    for bad in ("pc'; Remove-Item C:\\", "a b", "-x"):
        with pytest.raises(remote.RemoteError):
            remote.build_command(bad)
    with pytest.raises(remote.RemoteError):
        remote.build_command("pc", "ana'; calc")


def test_parse_output_normalizes_single_items():
    text = "WARNING: algo\n" + json.dumps(
        {"schema": 1, "host": "X", "processes": {"pid": 4, "ppid": 0, "name": "System"}, "autoruns": None}
    )
    data = remote.parse_output(text)
    assert data["processes"][0]["pid"] == 4 and data["autoruns"] == [] and data["connections"] == []
    with pytest.raises(remote.RemoteError):
        remote.parse_output('{"schema": 99}')
    with pytest.raises(remote.RemoteError):
        remote.parse_output("Acceso denegado")


def test_autorun_filtering_matches_autorunsc_rules():
    data = remote.parse_output((SAMPLES / "remote_sample.json").read_text(encoding="utf-8"))
    names = {f.name for f in remote.autorun_findings(data)}
    assert {"OneSyncHelper", "WinSysHelper", "\\UpdaterCheck", "Zoom"} <= names
    assert "Spooler" not in names and "OneDrive" not in names  # Microsoft sin abuso


def test_engine_remote_dry_run(tmp_path):
    opts = TriageOptions(
        autoruns=True, processes=True, network=True, scan_user=True, dry_run=True, config_dir=tmp_path,
        remote_host="demo",
    )  # fmt: skip
    res = TriageEngine(opts, {}).run()
    assert res.host == "PC-CONTABILIDAD" and res.user == "admin.ti" and res.admin
    assert "remote:demo" in res.modules and "scan-user" not in res.modules
    assert res.processes and res.connections
    assert max(f.score for f in res.findings) >= 70


def test_cli_remote_dry_run(tmp_path):
    assert cli.main(["--dry-run", "--remote", "srv-01", "--config-dir", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(next((tmp_path / "reportes").glob("*.json")).read_text(encoding="utf-8"))
    assert data["host"] == "SRV-01"
