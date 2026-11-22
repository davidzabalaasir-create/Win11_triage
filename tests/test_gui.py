"""Pruebas de humo de la interfaz: se omiten si no hay Tk o pantalla disponible."""

import csv
import time

import pytest

ctk = pytest.importorskip("customtkinter")
tk = pytest.importorskip("tkinter")


@pytest.fixture
def app(tmp_path):
    from win11_triage.gui import app as gui_app

    try:
        a = gui_app.TriageApp(tmp_path)
    except tk.TclError as e:  # sin pantalla (CI Linux sin Xvfb)
        pytest.skip(f"Tk no disponible: {e}")
    a.withdraw()
    a.var_dry.set(True)
    yield a
    a.destroy()


def _pump_until(app, cond, timeout=20):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        app.update()
        time.sleep(0.02)
    assert cond(), "la GUI no terminó a tiempo"


def _run(app):
    app.result = None
    app.start()
    _pump_until(app, lambda: app.result is not None and not app.worker.is_alive())


def test_dry_run_populates_dashboard_table_and_history(app, tmp_path):
    _run(app)
    assert app.cards["detected"].value.cget("text") == "15"
    assert app.cards["new"].value.cget("text") == "—"  # primer análisis
    assert app.filter_btn.get() == "Detectados"
    assert len(app.tree.get_children()) == 15
    assert len(app.priority_tree.get_children()) == 5
    assert len(app.conn_tree.get_children()) > 0
    assert app.gauge.score == 100
    assert any(p.suffix == ".html" for p in app.reports)  # formato por defecto: HTML
    assert len(app.history_entries) == 1  # el JSON se guarda siempre para el historial

    app.filter_btn.set("Todos")
    app.search.insert(0, "T1546.008")  # búsqueda por técnica ATT&CK
    app.render_table()
    assert [app.findings[int(i)].name for i in app.tree.get_children()] == ["sethc.exe"]


def test_second_run_compares_with_previous(app):
    _run(app)
    time.sleep(1.1)  # informes con distinto segundo
    _run(app)
    assert app.has_previous and app.cards["new"].value.cget("text") == "0"
    assert len(app.history_entries) == 2


def test_detail_shows_signals(app):
    _run(app)
    first = app.tree.get_children()[0]
    app.tree.selection_set(first)
    app.update()
    text = app.detail_box.get("1.0", "end")
    assert "Por qué:" in text and "score" in text


def test_export_csv_and_whitelist(app, tmp_path, monkeypatch):
    from win11_triage.gui import app as gui_app

    _run(app)
    out = app.export_csv(tmp_path / "vista.csv")
    rows = list(csv.reader(out.open(encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][:3] == ["estado", "score", "origen"] and len(rows) == 16

    monkeypatch.setattr(gui_app.messagebox, "askyesno", lambda *a, **k: True)
    before = len(app.findings)
    app.tree.selection_set(app.tree.get_children()[0])
    app.update()
    app.whitelist_selected(by_hash=False)
    assert (tmp_path / "whitelist.json").exists()
    assert len(app.findings) < before


def test_history_reload_and_presets(app):
    _run(app)
    app.refresh_history()
    app.history_tree.selection_set("0")
    app.result = None
    app.load_history_entry()
    assert app.result is not None and "historial" in app.subtitle.cget("text")
    app.apply_preset("Rápido")
    assert app.module_vars["processes"].get() and not app.module_vars["vt"].get()
