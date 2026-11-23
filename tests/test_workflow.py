"""Revisión del analista, comparación de análisis, paquete de evidencias, cronología y CLI."""

import json
import zipfile
from unittest import mock

import pytest

from win11_triage import cli, report, updates
from win11_triage.models import Finding
from win11_triage.review import PENDING, ReviewStore


def _run(tmp_path, *extra):
    cli.main(["--dry-run", "--config-dir", str(tmp_path), "--format", "json", "--no-color", *extra])
    return sorted((tmp_path / "reportes").glob("*.json"))[-1]


def test_review_store_persists_and_forgets_pending(tmp_path):
    store = ReviewStore(tmp_path)
    store.set("k1", state="Falso positivo", note="  Agente de backup  ", name="x.exe")
    store.set("k2", state="Confirmado")
    again = ReviewStore(tmp_path)
    assert again.get("k1")["state"] == "Falso positivo" and again.get("k1")["note"] == "Agente de backup"
    again.set("k2", state=PENDING)
    assert "k2" not in ReviewStore(tmp_path).data
    assert again.counts(["k1", "k2", "k3"]) == {"Pendiente": 2, "En revisión": 0, "Falso positivo": 1, "Confirmado": 0}
    with pytest.raises(ValueError):
        again.set("k1", state="Inventado")


def test_reviews_flow_into_reports(tmp_path):
    first = report.load_json(_run(tmp_path))
    target = first.findings[0]
    ReviewStore(tmp_path).set(target.key, state="Confirmado", note="Persistencia maliciosa")
    data = json.loads(_run(tmp_path).read_text(encoding="utf-8"))
    reviewed = [f for f in data["findings"] if f.get("review")]
    assert reviewed and reviewed[0]["review"]["state"] == "Confirmado"
    assert reviewed[0]["key"] == target.key


def test_diff_results(tmp_path):
    a = report.load_json(_run(tmp_path))
    b = report.load_json(_run(tmp_path))
    gone = b.sections[next(iter(b.sections))].pop(0)
    extra = Finding("sigcheck", "nuevo.exe", "C:\\Users\\u\\AppData\\nuevo.exe", "", "Unsigned", "")
    b.sections[next(iter(b.sections))].append(extra)
    d = report.diff_results(a, b)
    assert [f.name for f in d.new] == ["nuevo.exe"]
    assert [f.key for f in d.resolved] == [gone.key]


def test_evidence_zip_contents_and_integrity(tmp_path):
    _run(tmp_path, "--evidence")
    zpath = next((tmp_path / "reportes").glob("*_evidencias.zip"))
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        assert {"LEEME.txt", "SHA256SUMS.txt", "iocs_sha256.txt"} <= names
        assert {n.rsplit(".", 1)[-1] for n in names} >= {"html", "md", "json", "csv", "txt"}
        import hashlib

        for line in zf.read("SHA256SUMS.txt").decode().splitlines():
            digest, name = line.split("  ", 1)
            assert hashlib.sha256(zf.read(name)).hexdigest() == digest


def test_timeline_sorted_desc():
    fs = [
        Finding("event", n, "", "", "", "", created=c)
        for n, c in (("a", "2026-01-01T00:00:00"), ("b", "2026-03-01T00:00:00"), ("c", ""))
    ]
    assert [f.name for f in report.timeline(fs)] == ["b", "a"]


def test_min_score_and_fail_on_score(tmp_path):
    data = json.loads(_run(tmp_path, "--min-score", "80").read_text(encoding="utf-8"))
    assert data["findings"] and all(f["score"] >= 80 for f in data["findings"])
    # --fail-on-score solo afecta a ejecuciones reales; el dry-run siempre devuelve 0
    assert (
        cli.main(["--dry-run", "--no-report", "--fail-on-score", "10", "--config-dir", str(tmp_path), "--no-color"])
        == 0
    )


def test_check_update(monkeypatch):
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"tag_name": "v9.9.9", "html_url": "https://example.invalid/r"}
    resp.raise_for_status.return_value = None
    monkeypatch.setattr(updates.requests, "get", lambda *a, **k: resp)
    info = updates.check_latest()
    assert info.available and info.latest == "9.9.9"
    assert cli.main(["--check-update", "--no-color"]) == 0
    assert updates.parse_version("v2.10.0") > updates.parse_version("2.9.9")
