import hashlib

import pytest

from win11_triage import collectors
from win11_triage.models import Finding


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-8-sig", "cp1252"])
def test_decode_output_handles_sysinternals_encodings(encoding):
    text = '"Entry","Signer"\n"Café","(Verified) Contoso"\n'
    assert collectors.decode_output(text.encode(encoding)) == text


def test_parse_csv_skips_banner_lines():
    text = "Sysinternals banner\nCopyright\n\nPath,Verified\nC:\\a.exe,Unsigned\n"
    assert collectors.parse_csv(text, "Verified") == [{"Path": "C:\\a.exe", "Verified": "Unsigned"}]


def test_parse_csv_without_header_returns_empty():
    assert collectors.parse_csv("nada que ver", "Verified") == []


@pytest.mark.parametrize(
    ("signer", "expected"),
    [
        ("(Verified) Microsoft Windows", False),
        ("(Verified) Microsoft Corporation", False),
        ("(Not verified) Microsoft Corporation", True),
        ("(Verified) Google LLC", True),
        ("", True),
    ],
)
def test_is_non_microsoft(signer, expected):
    assert collectors.is_non_microsoft(signer) is expected


def test_parse_autoruns_filters_microsoft_and_section_rows(autoruns_findings):
    names = {f.name for f in autoruns_findings}
    assert "SecurityHealth" not in names and "OneDrive" not in names  # Microsoft sin abuso: fuera
    assert {"UpdChk", "WinUpdateHelper", "sethc.exe"} <= names  # Microsoft usado de forma sospechosa: dentro
    assert {"OneSyncHelper", "\\UpdaterCheck", "\\GoogleUpdateTaskMachineUA"} <= names
    assert all(len(f.sha256) == 64 for f in autoruns_findings)


def test_parse_autoruns_marks_third_party_signatures(autoruns_findings):
    by_name = {f.name: f for f in autoruns_findings}
    assert by_name["\\GoogleUpdateTaskMachineUA"].signed_ok
    assert not by_name["OneSyncHelper"].signed_ok
    assert by_name["\\UpdaterCheck"].signature == "(sin firma)"


def test_parse_sigcheck_skips_signed_and_resolves_publisher(sigcheck_findings):
    assert len(sigcheck_findings) == 5
    by_name = {f.name: f for f in sigcheck_findings}
    assert by_name["helper.dll"].publisher == "Helper Inc"
    assert by_name["setup_tmp.exe"].publisher == "(desconocido)"


def test_sha256_file(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"win11-triage")
    assert collectors.sha256_file(str(p)) == hashlib.sha256(b"win11-triage").hexdigest()
    assert collectors.sha256_file(str(tmp_path / "missing")) == ""


def test_parse_tcpvcon_ignores_noise(samples):
    text = "basura\n" + (samples / "tcpvcon_sample.csv").read_text(encoding="utf-8") + "UDP,x.exe,1\n"
    conns = collectors.parse_tcpvcon(text)
    assert len(conns) == 5
    assert conns[0].process == "syncsvc.exe"
    assert conns[0].remote == "185.220.101.7:443"


def test_correlate_connections_by_image_name(samples, autoruns_findings):
    conns = collectors.parse_tcpvcon((samples / "tcpvcon_sample.csv").read_text(encoding="utf-8"))
    matched = collectors.correlate_connections(autoruns_findings, conns)
    by_name = {f.name: f for f in autoruns_findings}
    assert matched == 3
    assert len(by_name["OneSyncHelper"].connections) == 2


def test_run_tool_raises_collector_error_on_missing_binary(tmp_path):
    with pytest.raises(collectors.CollectorError):
        collectors.run_tool(tmp_path / "no-existe.exe", [])


def test_image_name_handles_quotes():
    f = Finding("a", "n", '"C:\\Program Files\\App\\app.EXE"', "", "", "")
    assert f.image_name == "app.exe"
