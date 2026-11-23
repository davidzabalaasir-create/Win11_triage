"""Motor Sigma: modificadores, condiciones, reglas incluidas y muestra de Sysmon."""

from win11_triage import collectors_events as ce
from win11_triage import engine, sigma
from win11_triage.collectors_events import Event

SYS = sigma.SYSMON


def _rule(detection, logsource=None, level="high"):
    return sigma.SigmaRule(
        "t", "id-t", level, ["attack.t1059.001"], logsource or {"category": "process_creation"}, detection
    )


def _proc(**data):
    return Event(SYS, 1, "2026-01-01T00:00:00", data)


def test_modifiers_and_wildcards():
    ev = _proc(Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami /all")
    assert _rule({"s": {"Image|endswith": r"\CMD.exe"}, "condition": "s"}).matches(ev)
    assert _rule({"s": {"CommandLine|contains|all": ["whoami", "/all"]}, "condition": "s"}).matches(ev)
    assert not _rule({"s": {"CommandLine|contains|all": ["whoami", "/priv"]}, "condition": "s"}).matches(ev)
    assert _rule({"s": {"Image": "*\\system32\\c?d.exe"}, "condition": "s"}).matches(ev)
    assert _rule({"s": {"CommandLine|re": r"who\w+"}, "condition": "s"}).matches(ev)
    assert not _rule({"s": {"Missing": "x"}, "condition": "s"}).matches(ev)


def test_conditions():
    ev = _proc(Image="a.exe", CommandLine="b")
    det = {"sel_a": {"Image": "a.exe"}, "sel_b": {"CommandLine": "zzz"}, "f": {"Image": "a.exe"}}
    for cond, want in [
        ("sel_a and not sel_b", True),
        ("sel_a and sel_b", False),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("(sel_b or sel_a) and not f", False),
        ("1 of them", True),
    ]:
        assert _rule({**det, "condition": cond}).matches(ev) is want, cond


def test_logsource_and_4688_normalization():
    ev = Event("Security", 4688, "t", {"NewProcessName": r"C:\x\reg.exe", "CommandLine": r"reg save HKLM\SAM s"})
    rule = _rule({"s": {"Image|endswith": r"\reg.exe"}, "condition": "s"})
    assert rule.matches(ev)
    assert not _rule({"s": {"Image|endswith": r"\reg.exe"}, "condition": "s"}, {"category": "dns_query"}).matches(ev)
    svc = _rule({"s": {"EventID": 7045}, "condition": "s"}, {"product": "windows", "service": "system"})
    assert svc.matches(Event("System", 7045, "t", {"ImagePath": "x"}))


def test_cidr():
    ev = Event(SYS, 3, "t", {"Image": "p.exe", "DestinationIp": "192.168.1.5"})
    r = _rule({"p": {"DestinationIp|cidr": "192.168.0.0/16"}, "condition": "p"}, {"category": "network_connection"})
    assert r.matches(ev)


def test_bundled_rules_on_sample():
    rules, warnings = sigma.load_rules()
    assert len(rules) >= 10 and not warnings
    events = ce.parse_events(engine.sample_text("sysmon_sample.xml"))
    found = sigma.scan_events(events, rules)
    names = {f.name for f in found}
    assert "Borrado de copias de seguridad (preparación de ransomware)" in names
    assert "Acceso a credenciales (LSASS o SAM)" in names
    assert not any("notepad" in f.path.lower() for f in found)  # evento benigno
    # la conexión a 192.168.x no dispara la regla de salida a Internet
    net = [f for f in found if f.name.startswith("Intérprete de scripts")]
    assert len(net) == 1 and "203.0.113.50" in net[0].cmdline
    grouped = next(f for f in found if f.path.endswith("p.exe") and f.name.startswith("Ejecución"))
    assert "2 veces" in grouped.location
    office = next(f for f in found if f.name.startswith("Office"))
    assert office.sha256.startswith("3f1a") and "T1204.002" in office.attack
    assert len({f.key for f in found}) == len(found)  # identidades únicas


def test_user_rules_and_bad_files(tmp_path):
    (tmp_path / "mine.yml").write_text(
        "title: Mi regla\nid: mine\nlevel: low\nlogsource: {category: process_creation}\n"
        "detection:\n  s:\n    Image|endswith: notepad.exe\n  condition: s\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.yml").write_text("title: [sin cerrar\n", encoding="utf-8")
    rules, warnings = sigma.load_rules(tmp_path)
    assert any(r.id == "mine" for r in rules) and len(warnings) == 1
    events = ce.parse_events(engine.sample_text("sysmon_sample.xml"))
    mine = [f for f in sigma.scan_events(events, rules) if f.name == "Mi regla"]
    assert mine and mine[0].score == sigma.LEVEL_WEIGHT["low"]


def test_engine_dry_run_sigma(tmp_path):
    opts = engine.TriageOptions(sigma=True, dry_run=True, config_dir=tmp_path)
    res = engine.TriageEngine(opts, {}).run()
    assert "sigma" in res.modules
    assert len(res.sections[engine.SECTION_SIGMA]) >= 9
