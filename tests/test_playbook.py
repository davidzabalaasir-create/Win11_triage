"""«¿Qué hago con esto?»: recomendaciones por señal y por estado."""

from win11_triage import cli, playbook
from win11_triage.models import Finding, Signal


def _f(*signals):
    f = Finding("autoruns", "x.exe", r"C:\x.exe", "", "", "")
    for s in signals:
        f.add(s)
    return f


def test_most_specific_prefix_wins():
    f = _f(Signal("CMD_PS_ENCODED", "t", 40))
    assert "codificado" in playbook.advice_for(f).summary
    f = _f(Signal("CMD_CERTUTIL", "t", 40))
    assert "Living off the Land" in playbook.advice_for(f).summary


def test_steps_are_combined_without_duplicates_and_status_added():
    f = _f(Signal("VT_DETECTED", "vt", 100), Signal("PERSIST_LOLBIN", "p", 30))
    adv = playbook.advice_for(f)
    assert len(adv.steps) == len(set(adv.steps))
    assert adv.steps[0].startswith("Desconecta")  # lo más grave primero
    assert any("Confirmado" in s for s in adv.steps)  # cierre según estado (rojo)


def test_unknown_signal_falls_back_to_status():
    f = _f(Signal("ALGO_NUEVO", "t", 35))
    assert playbook.advice_for(f).summary.startswith("No es necesariamente malo")
    assert "1." in playbook.as_text(f)


def test_negative_signals_ignored():
    f = _f(Signal("SIG_TRUSTED", "firmado", -15))
    f.signed_ok = True
    assert playbook.advice_for(f).summary == "No hay indicios de riesgo."


def test_cli_explain_and_reports(tmp_path, capsys):
    assert cli.main(["--dry-run", "--config-dir", str(tmp_path), "--format", "all", "--explain", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert out.count("¿Qué hago con esto?") >= 5
    html = next((tmp_path / "reportes").glob("*.html")).read_text(encoding="utf-8")
    md = next((tmp_path / "reportes").glob("*.md")).read_text(encoding="utf-8")
    assert "class='todo'" in html and "**¿Qué hago con esto?**" in md
