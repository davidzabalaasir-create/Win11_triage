import json

import pytest

from win11_triage import cli, env_check
from win11_triage.models import Finding, Status


def test_status_rules():
    base = dict(source="s", name="n", path="p", publisher="", signature="", sha256="h")
    assert Finding(**base).status is Status.UNKNOWN
    assert Finding(**base, signed_ok=True).status is Status.CLEAN
    assert Finding(**base, vt={"found": True, "malicious": 2}).status is Status.DETECTED
    assert Finding(**base, vt={"found": True, "malicious": 0, "suspicious": 1}).status is Status.UNKNOWN
    assert Finding(**base, vt={"found": False}).status is Status.UNKNOWN


def test_dry_run_enables_all_modules(tmp_path):
    a = cli.parse_args(["--dry-run", "--config-dir", str(tmp_path)])
    assert a.autoruns and a.scan_user and a.network and a.vt
    assert a.output_dir == tmp_path.resolve() / "reportes"


def test_vt_implies_collectors(tmp_path):
    a = cli.parse_args(["--vt", "--config-dir", str(tmp_path)])
    assert a.options.autoruns and a.options.scan_user and not a.options.network


def test_negative_vt_limit_rejected():
    with pytest.raises(SystemExit):
        cli.parse_args(["--vt-limit", "-1"])


def test_dry_run_end_to_end(tmp_path):
    code = cli.main(["--dry-run", "--config-dir", str(tmp_path), "--format", "both", "--no-color"])
    assert code == cli.EXIT_OK
    reports = sorted((tmp_path / "reportes").iterdir())
    assert [p.suffix for p in reports] == [".json", ".md"]

    data = json.loads(reports[0].read_text(encoding="utf-8"))
    assert data["dry_run"] is True
    assert data["summary"] == {"DETECTADO": 3, "DESCONOCIDO": 1, "LIMPIO": 2}
    assert data["whitelisted"] == 1
    assert data["findings"][0]["status"] == "DETECTADO"

    md = reports[1].read_text(encoding="utf-8")
    assert "DRY-RUN" in md and "OneSyncHelper" in md and "185.220.101.7:443" in md
    # El dry-run no debe tocar la caché ni la lista blanca reales.
    assert not (tmp_path / "vt_cache.json").exists()
    assert not (tmp_path / "whitelist.json").exists()


def test_dry_run_vt_limit_skips_queries(tmp_path):
    cli.main(["--dry-run", "--vt-limit", "1", "--config-dir", str(tmp_path), "--format", "json", "--no-color"])
    data = json.loads(next((tmp_path / "reportes").glob("*.json")).read_text(encoding="utf-8"))
    assert data["vt_stats"]["network"] == 1
    assert data["vt_stats"]["skipped"] == 4


def test_missing_tools_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(env_check, "is_windows", lambda: True)
    monkeypatch.setattr(env_check, "find_tool", lambda n: env_check.ToolStatus(n, None, ""))
    assert cli.main(["--autoruns", "--config-dir", str(tmp_path), "--no-color"]) == cli.EXIT_ENV


def test_markdown_escapes_untrusted_values():
    from win11_triage.report import _code, _md

    assert _md("a|b<script>") == "a\\|b&lt;script&gt;"
    assert _code("C:\\a`b") == "`` C:\\a`b ``"


def test_connections_table_dedupes_shared_processes():
    from win11_triage.models import Connection
    from win11_triage.report import connections_table

    c = Connection("TCP", "upd.exe", "1", "ESTABLISHED", "a:1", "b:2")
    base = dict(source="s", name="n", path="p", publisher="", signature="", sha256="h")
    f1 = Finding(**base, connections=[c])
    f2 = Finding(**base, connections=[c], vt={"found": True, "malicious": 1})
    assert connections_table([f1, f2]).row_count == 1
