"""Prueba de humo de la interfaz: se omite si no hay Tk o pantalla disponible."""

import time

import pytest

ctk = pytest.importorskip("customtkinter")
tk = pytest.importorskip("tkinter")


@pytest.fixture
def app(tmp_path):
    from win11_triage import gui

    try:
        a = gui.TriageApp(tmp_path)
    except tk.TclError as e:  # sin pantalla (CI Linux sin Xvfb)
        pytest.skip(f"Tk no disponible: {e}")
    a.withdraw()
    yield a
    a.destroy()


def _pump_until(app, cond, timeout=15):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        app.update()
        time.sleep(0.02)
    assert cond(), "la GUI no terminó a tiempo"


def test_gui_dry_run_populates_views(app, tmp_path):
    app.var_dry.set(True)
    app._start()
    _pump_until(app, lambda: app.result is not None)
    assert app.card_values["detected"].cget("text") == "3"
    assert app.filter_btn.get() == "Detectados"
    assert len(app.tree.get_children()) == 3
    assert len(app.conn_tree.get_children()) == 4
    assert app.reports and app.reports[0].exists()

    app.filter_btn.set("Todos")
    app._render_table()
    assert len(app.tree.get_children()) == 6
    app.search.insert(0, "helper.dll")
    app._render_table()
    assert len(app.tree.get_children()) == 1


def test_gui_whitelist_removes_item(app, tmp_path, monkeypatch):
    from win11_triage import gui

    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    app.var_dry.set(True)
    app._start()
    _pump_until(app, lambda: app.result is not None)
    app.filter_btn.set("Todos")
    app._render_table()
    first = app.tree.get_children()[0]
    app.tree.selection_set(first)
    app.update()
    app._whitelist_selected(by_hash=True)
    assert (tmp_path / "whitelist.json").exists()
    assert len(app.tree.get_children()) < 6
