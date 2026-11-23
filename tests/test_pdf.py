"""Resumen ejecutivo en PDF."""

from win11_triage import cli, report
from win11_triage.engine import TriageEngine, TriageOptions
from win11_triage.report_pdf import render_pdf


def test_pdf_one_page(tmp_path):
    res = TriageEngine(TriageOptions(dry_run=True, autoruns=True, sigma=True, config_dir=tmp_path), {}).run()
    out = render_pdf(res, tmp_path / "x.pdf")
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 3000
    assert b"/Count 1" in data  # una sola página


def test_pdf_empty_result(tmp_path):
    res = TriageEngine(TriageOptions(dry_run=True, browsers=True, config_dir=tmp_path), {}).run()
    res.sections = {}
    assert render_pdf(res, tmp_path / "vacío.pdf").exists()


def test_cli_format_pdf(tmp_path):
    assert cli.main(["--dry-run", "--config-dir", str(tmp_path), "--format", "pdf"]) == 0
    pdfs = list((tmp_path / "reportes").glob("*_ejecutivo.pdf"))
    assert len(pdfs) == 1 and "pdf" in report.FORMAT_CHOICES
