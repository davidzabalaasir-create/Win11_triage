from win11_triage import collectors_events as ev


def test_parse_sample_events(samples):
    events = ev.parse_events((samples / "events_sample.xml").read_text(encoding="utf-8"))
    assert [e.event_id for e in events] == [7045, 4698, 1116]
    assert events[0].data["ServiceName"] == "WinSysHelper"
    assert events[0].time.startswith("2026-11-21T22:15")


def test_event_to_finding_types(samples):
    events = ev.parse_events((samples / "events_sample.xml").read_text(encoding="utf-8"))
    svc, task, defender = (ev.event_to_finding(e) for e in events)
    assert svc.path.lower().endswith("cmd.exe") and "-enc" in svc.cmdline
    assert task.path.endswith("syncsvc.exe") and task.cmdline.endswith("/silent")
    assert defender.path == "C:\\Users\\usuario\\Downloads\\factura.pdf.exe"
    assert defender.signals[0].id == "DEFENDER_DETECTION" and defender.signals[0].weight == 80


def test_build_query_and_exe_parsing():
    q = ev.build_query((1116, 1117), 2)
    assert "EventID=1116 or EventID=1117" in q and str(2 * 86400000) in q
    assert ev._exe_from_cmdline('"C:\\Program Files\\a b\\x.exe" -k') == "C:\\Program Files\\a b\\x.exe"
    assert ev._exe_from_cmdline("C:\\x\\y.exe /run") == "C:\\x\\y.exe"
    assert ev.parse_events("") == []
