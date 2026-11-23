"""Idiomas: traducción, patrones, informes y PDF en inglés."""

import pytest

from win11_triage import cli, i18n, playbook, sigma
from win11_triage.i18n_en import EN
from win11_triage.models import Finding, Signal


@pytest.fixture
def english():
    i18n.set_language("en")
    yield
    i18n.set_language("es")


def test_t_spanish_is_identity():
    assert i18n.t("Nuevo análisis") == "Nuevo análisis"


def test_t_english_exact_pattern_and_fallback(english):
    assert i18n.t("Nuevo análisis") == "New scan"
    assert i18n.t("Hallazgos  (31)") == "Findings  (31)"
    assert i18n.t("svchost.exe fuera de System32") == "svchost.exe outside System32"
    assert i18n.t("texto sin traducir") == "texto sin traducir"
    assert i18n.t("  Analizar") == "  Scan"
    assert i18n.set_language("fr") == "es"  # idioma desconocido → español


def test_dictionary_has_no_empty_values():
    assert all(v.strip() for v in EN.values())


def test_playbook_and_sigma_titles(english):
    f = Finding("autoruns", "x", r"C:\x.exe", "", "", "")
    f.add(Signal("VT_DETECTED", "vt", 100))
    assert playbook.advice_for(f).summary.startswith("Several VirusTotal")
    rules, _ = sigma.load_rules()
    assert any(r.title == "Credential access (LSASS or SAM)" for r in rules)


def test_cli_lang_en_reports(tmp_path):
    try:
        assert cli.main(["--dry-run", "--lang", "en", "--config-dir", str(tmp_path), "--format", "all"]) == 0
    finally:
        i18n.set_language("es")
    md = next((tmp_path / "reportes").glob("*.md")).read_text(encoding="utf-8")
    html = next((tmp_path / "reportes").glob("*.html")).read_text(encoding="utf-8")
    assert "## Summary" in md and "| Field | Value |" in md and "**What should I do?**" in md
    assert "<h2>Prioritise this first</h2>" in html and "lang='en'" in html
    pdf = next((tmp_path / "reportes").glob("*.pdf")).read_bytes()
    assert pdf.startswith(b"%PDF")
