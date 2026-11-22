import json

import pytest

from win11_triage.models import Finding
from win11_triage.whitelist import Whitelist, WhitelistError


def _f(path="", sha=""):
    return Finding("autoruns", "n", path, "", "", sha)


def test_matches_glob_prefix_and_hash():
    wl = Whitelist(paths=["C:\\Tools\\*", "D:\\Apps\\"], hashes=["ABC"])
    assert wl.matches(_f("c:\\tools\\x.exe"))
    assert wl.matches(_f("D:/Apps/sub/y.exe"))
    assert wl.matches(_f("e:\\z.exe", "abc"))
    assert not wl.matches(_f("e:\\z.exe", "def"))


def test_expands_environment_variables(monkeypatch):
    monkeypatch.setenv("APPDATA", "C:\\Users\\u\\AppData\\Roaming")
    wl = Whitelist(paths=["%APPDATA%\\Zoom\\*"])
    assert wl.matches(_f("C:\\Users\\u\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"))


def test_load_creates_template(tmp_path):
    p = tmp_path / "whitelist.json"
    assert len(Whitelist.load(p)) == 0
    assert json.loads(p.read_text())["paths"] == []


def test_load_rejects_invalid_json(tmp_path):
    p = tmp_path / "whitelist.json"
    p.write_text("[1, 2")
    with pytest.raises(WhitelistError):
        Whitelist.load(p)


def test_filter_counts_ignored():
    kept, n = Whitelist(hashes=["x"]).filter([_f(sha="x"), _f(sha="y")])
    assert n == 1 and kept[0].sha256 == "y"


def test_expand_win_vars_is_case_insensitive_and_keeps_unknown(monkeypatch):
    from win11_triage.utils import expand_win_vars

    monkeypatch.setenv("WINDIR", "C:\\Windows")
    assert expand_win_vars("%windir%\\x.exe") == "C:\\Windows\\x.exe"
    assert expand_win_vars("%NO_EXISTE_XYZ%\\a") == "%NO_EXISTE_XYZ%\\a"
