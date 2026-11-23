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
    assert app.cards["detected"].value.cget("text") == "23"
    assert app.cards["new"].value.cget("text") == "—"  # primer análisis
    assert app.filter_btn.get() == "Detectados"
    assert len(app.tree.get_children()) == 23
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
    text = app.detail_text()
    assert "Por qué:" in text and "score" in text and "SHA-256:" in text


def test_export_csv_and_whitelist(app, tmp_path):
    _run(app)
    out = app.export_csv(tmp_path / "vista.csv")
    rows = list(csv.reader(out.open(encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][:3] == ["estado", "score", "origen"] and len(rows) == 24

    before = len(app.findings)
    app.tree.selection_set(app.tree.get_children()[0])
    app.update()
    app.whitelist_selected(by_hash=False)
    assert (tmp_path / "whitelist.json").exists()
    assert len(app.findings) < before
    # «Deshacer» desde el toast restaura el elemento y lo quita de la lista blanca
    toast_frame = next(w for w in app.place_slaves() if getattr(w, "_is_toast", False))
    buttons = [w for w in toast_frame.winfo_children() if isinstance(w, ctk.CTkButton)]
    undo_btn = next(b for b in buttons if "Deshacer" in b.cget("text"))
    undo_btn.invoke()
    assert len(app.findings) == before


def test_history_reload_and_presets(app):
    _run(app)
    app.refresh_history()
    app.history_tree.selection_set("0")
    app.result = None
    app.load_history_entry()
    assert app.result is not None and "historial" in app.subtitle.cget("text")
    app.apply_preset("Rápido")
    assert app.module_vars["processes"].get() and not app.module_vars["vt"].get()


def test_pages_theme_and_new_scan_dialog(app):
    from win11_triage.gui.dialogs import NewScanDialog

    for page in ("home", "findings", "network", "history", "settings"):
        app.show_page(page)
        app.update()
        assert app.page_title.cget("text")
    app.set_appearance("Claro")
    app.update()
    app.set_appearance("Oscuro")
    dlg = NewScanDialog(app)
    app.update()
    dlg.profile.set("Rápido")
    dlg._apply_profile("Rápido")
    assert app.module_vars["processes"].get() and not app.module_vars["vt"].get()
    dlg.destroy()


def test_empty_state_and_demo_button(app):
    assert app.home_empty.winfo_manager() == "grid"
    app.start_demo()
    _pump_until(app, lambda: app.result is not None and not app.worker.is_alive())
    assert app.home_empty.winfo_manager() == ""


def test_review_workflow_compare_and_evidence(app, tmp_path):
    from win11_triage.review import ReviewStore

    _run(app)
    app.filter_btn.set("Todos")
    app.render_table()
    first = app.tree.get_children()[0]
    app.tree.selection_set(first)
    app.update()
    app.set_review("Falso positivo")
    app.note_box.insert("1.0", "Herramienta interna")
    app.save_note()
    stored = ReviewStore(tmp_path).get(app.findings[int(first)].key)
    assert stored["state"] == "Falso positivo" and stored["note"] == "Herramienta interna"
    assert "Revisados 1/" in app.review_progress.cget("text")
    app.review_filter.set("Falso positivo")
    app.render_table()
    assert len(app.tree.get_children()) == 1

    zpath = app.export_evidence(tmp_path / "ev.zip")
    assert zpath.exists()

    time.sleep(1.1)
    _run(app)
    app.refresh_history()
    app.history_tree.selection_set(str(len(app.history_entries) - 1))  # el más antiguo
    app.compare_with_selected()
    app.update()
    dialogs = [w for w in app.winfo_children() if w.__class__.__name__ == "CompareDialog"]
    assert dialogs and dialogs[0].diff.new == [] and dialogs[0].diff.resolved == []
    dialogs[0].destroy()


def test_settings_integrations(app, tmp_path, monkeypatch):
    app.show_page("settings")
    app.update()
    app.webhook_entry.delete(0, "end")
    app.webhook_entry.insert(0, "http://inseguro")
    monkeypatch.setattr("tkinter.messagebox.showerror", lambda *a, **k: None)
    app.save_webhook()
    assert (
        "WIN11_TRIAGE_WEBHOOK" not in (tmp_path / ".env").read_text(encoding="utf-8")
        if (tmp_path / ".env").exists()
        else True
    )
    app.webhook_entry.delete(0, "end")
    app.webhook_entry.insert(0, "https://hooks.slack.com/services/T/B/x")
    app.save_webhook()
    assert "hooks.slack.com" in (tmp_path / ".env").read_text(encoding="utf-8")
    monkeypatch.delenv("WIN11_TRIAGE_WEBHOOK", raising=False)

    sent = []
    monkeypatch.setattr("win11_triage.alerts.notify_toast", lambda t, b: sent.append((t, b)) or True)
    monkeypatch.setattr(app, "focus_displayof", lambda: None)  # ventana en segundo plano
    _run(app)
    _pump_until(app, lambda: bool(sent), timeout=5)
    assert "win11-triage" in sent[0][0]


def test_english_interface(tmp_path):
    import json

    from win11_triage import i18n
    from win11_triage.gui import app as gui_app

    (tmp_path / "gui_settings.json").write_text(json.dumps({"language": "en"}), encoding="utf-8")
    try:
        a = gui_app.TriageApp(tmp_path)
    except tk.TclError as e:
        pytest.skip(f"Tk no disponible: {e}")
    try:
        a.withdraw()
        a.update()
        assert a.page_title.cget("text") == "Home"
        assert "Scan" in a.run_btn.cget("text")
        texts = [b.cget("text") for b in a.nav.rows["settings"][2:]]
        assert any("Settings" in x for x in texts)
    finally:
        a.destroy()
        i18n.set_language("es")


def test_assistant_page(app, monkeypatch):
    from test_agent import FakeLLM

    from win11_triage import agent

    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setattr(agent, "new_session", lambda: FakeLLM())
    monkeypatch.setattr("win11_triage.gui.app.load_dotenv", lambda *a, **k: None)
    _run(app)
    app.show_page("assistant")
    app.chat_entry.insert(0, "¿Qué reviso primero?")
    app.ask_agent()
    _pump_until(app, lambda: "Lo más grave" in app.chat_box.get("1.0", "end"))
    assert str(app.chat_send.cget("state")) == "normal"
