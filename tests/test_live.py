import json

from win11_triage import collectors_live as live
from win11_triage.models import Finding


def _sample(samples):
    return live.parse_sample(json.loads((samples / "processes_sample.json").read_text(encoding="utf-8")))


def test_process_findings_selects_only_suspicious(samples):
    procs, _ = _sample(samples)
    found = {f.pid: f for f in live.process_findings(procs, compute_hashes=False)}
    assert set(found) == {4120, 6604, 5300, 7720}  # benignos (System32, Program Files) fuera
    assert found[5300].parent == "winword.exe"
    assert found[7720].location.startswith("PID 7720")


def test_attach_connections_by_pid_and_exact_path(samples):
    procs, conns = _sample(samples)
    proc_f = live.process_findings(procs, compute_hashes=False)
    # Un hallazgo de fichero con la misma ruta (distinto caso) que el svchost falso
    file_f = Finding(
        "sigcheck", "svchost.exe", "c:\\users\\usuario\\appdata\\local\\microsoft\\svchost.exe", "", "", ""
    )
    legit = Finding("autoruns", "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "", "", "")
    live.attach_connections([*proc_f, file_f, legit], conns, procs)
    assert [c.remote for c in file_f.connections] == ["198.51.100.23:4444"]
    assert [c.remote for c in legit.connections] == ["20.42.65.92:443"]  # no se mezclan por nombre
    assert any(s.id == "NET_ACTIVE" for s in file_f.signals)


def test_external_address_filter():
    assert live._is_external("8.8.8.8:53")
    assert not live._is_external("127.0.0.1:80")
    assert not live._is_external("[::1]:80")


def test_missing_image_is_kept(samples):
    procs = {1: live.ProcInfo(1, 0, "x.exe", "C:\\Program Files\\x.exe", "", "", exe_missing=True)}
    found = live.process_findings(procs, compute_hashes=False)
    assert [s.id for s in found[0].signals] == ["PROC_IMAGE_MISSING"]
