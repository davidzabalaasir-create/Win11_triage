"""Alertas: selección de novedades, payloads de webhooks, JSONL y programación."""

import json
from datetime import datetime

from win11_triage import alerts, cli, report, scheduler
from win11_triage.engine import TriageEngine, TriageOptions
from win11_triage.models import Finding, Signal


def _res(*findings):
    r = report.TriageResult(
        host="PC", user="u", started=datetime(2026, 11, 22, 9, 0, 0), dry_run=False, admin=False, tools={}
    )
    r.sections = {"s": list(findings)}
    return r


def _f(name, weight, path=None):
    f = Finding("autoruns", name, path or rf"C:\{name}.exe", "", "", "")
    f.add(Signal("X", "x", weight))
    return f


def test_select_only_new_and_worse():
    prev = _res(_f("a", 80), _f("b", 30), _f("c", 50))
    cur = _res(_f("a", 80), _f("b", 60), _f("d", 75), _f("e", 5))
    assert [f.name for f in alerts.select_alertable(cur)] == ["a", "d", "b"]
    assert [f.name for f in alerts.select_alertable(cur, prev, only_new=True)] == ["d", "b"]
    title, body = alerts.summary_text(cur, [], True)
    assert "Sin novedades" in body and "PC" in title


def test_webhook_kinds_and_payloads():
    assert alerts.webhook_kind("https://hooks.slack.com/services/x") == "slack"
    assert alerts.webhook_kind("https://acme.webhook.office.com/webhookb2/x") == "teams"
    assert alerts.webhook_kind("https://prod-1.westeurope.logic.azure.com/workflows/x") == "teams"
    assert alerts.webhook_kind("https://splunk:8088/services/collector/event") == "splunk"
    assert alerts.webhook_kind("https://wazuh.local/hook") == "json"
    r = _res(_f("evil", 90))
    items = alerts.select_alertable(r)
    slack = alerts.build_payload("slack", r, items, False)
    assert "evil" in json.dumps(slack) and slack["blocks"]
    teams = alerts.build_payload("teams", r, items, False)
    assert teams["attachments"][0]["content"]["type"] == "AdaptiveCard"
    generic = alerts.build_payload("json", r, items, False)
    ev = generic["findings"][0]
    assert ev["win11_triage"]["score"] == 90 and ev["host"]["name"] == "PC" and ev["event"]["kind"] == "alert"
    hec = alerts.build_payload("splunk", r, items, False)
    assert hec[0]["sourcetype"] == "win11_triage"


def test_send_webhook_uses_session(monkeypatch):
    sent = {}

    class R:
        def raise_for_status(self):
            pass

    class S:
        def post(self, url, **kw):
            sent.update(url=url, **kw)
            return R()

    r = _res(_f("evil", 90))
    assert alerts.send_webhook("https://hooks.slack.com/x", r, alerts.select_alertable(r), session=S()) == "slack"
    assert "blocks" in sent["json"]
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "tok")
    alerts.send_webhook("https://s:8088/services/collector", r, alerts.select_alertable(r), session=S())
    assert sent["headers"]["Authorization"] == "Splunk tok" and b"win11_triage" in sent["data"]


def test_jsonl_appends(tmp_path):
    r = _res(_f("a", 80), _f("b", 70))
    out = tmp_path / "x" / "f.jsonl"
    assert alerts.write_jsonl(out, r, r.findings) == 2
    alerts.write_jsonl(out, r, r.findings[:1])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and json.loads(lines[0])["rule"]["name"] == "a"


def test_toast_script_escapes():
    s = alerts.toast_script("a <b>", "x & y")
    assert "&lt;b&gt;" in s and "&amp;" in s and "ToastNotificationManager" in s


def test_scheduler_args_and_script(tmp_path):
    args = scheduler.schtasks_create_args(tmp_path / "s.cmd", "weekly", "7:05", admin=True)
    assert args[args.index("/SC") + 1] == "WEEKLY" and "07:05" in args and "/RL" in args and "MON" in args
    assert "conhost.exe --headless" in args[args.index("/TR") + 1]
    text = scheduler.script_text(tmp_path)
    assert "--alert-new" in text and "--notify" in text and str(tmp_path) in text
    for bad in (("hourly", "09:00"), ("daily", "25:00"), ("daily", "nueve")):
        try:
            scheduler.schtasks_create_args(tmp_path / "s.cmd", *bad, admin=False)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_cli_alert_new_and_jsonl(tmp_path, monkeypatch):
    out = tmp_path / "events.jsonl"
    base = ["--dry-run", "--config-dir", str(tmp_path), "--format", "json", "--jsonl", str(out), "--alert-new"]
    assert cli.main(base) == cli.EXIT_OK
    first = len(out.read_text(encoding="utf-8").splitlines())
    assert first > 5  # sin análisis anterior: se exporta todo lo relevante
    import time

    time.sleep(1.1)
    assert cli.main(base) == cli.EXIT_OK
    assert len(out.read_text(encoding="utf-8").splitlines()) == first  # nada nuevo


def test_engine_result_feeds_alerts(tmp_path):
    res = TriageEngine(TriageOptions(sigma=True, dry_run=True, config_dir=tmp_path), {}).run()
    items = alerts.select_alertable(res)
    assert items and items[0].score >= items[-1].score
