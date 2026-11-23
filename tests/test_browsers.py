"""Extensiones de navegador: lectura de perfiles Chromium/Firefox y señales."""

import json

from win11_triage import collectors_browsers as cb
from win11_triage import engine


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_chromium_profile_parsing(tmp_path):
    ud = tmp_path / "Google" / "Chrome" / "User Data"
    prof = ud / "Default"
    ext = prof / "Extensions" / "abc"
    _write(ext / "1.0_0" / "manifest.json", {"name": "old", "version": "1.0"})
    _write(
        ext / "2.0_0" / "manifest.json",
        {
            "name": "__MSG_appName__",
            "default_locale": "en",
            "version": "2.0",
            "permissions": ["nativeMessaging", "storage"],
            "content_scripts": [{"matches": ["<all_urls>"]}],
        },
    )
    _write(ext / "2.0_0" / "_locales" / "en" / "messages.json", {"appName": {"message": "Helper"}})
    _write(
        prof / "Secure Preferences",
        {"extensions": {"settings": {"abc": {"location": 4, "install_time": "13370000000000000"}}}},
    )
    exts = cb.collect_extensions(local=tmp_path, roaming=tmp_path / "none")
    assert len(exts) == 1
    e = exts[0]
    assert e["name"] == "Helper" and e["version"] == "2.0" and e["unpacked"] and not e["from_store"]
    assert e["installed"].startswith("2024")
    f = cb.extension_findings(exts)[0]
    ids = {s.id for s in f.signals}
    assert {"EXT_UNPACKED", "EXT_ALL_SITES", "EXT_PERMS"} <= ids and f.score >= 60
    assert f.source == "browser" and "T1176" in f.attack


def test_firefox_profile_parsing(tmp_path):
    prof = tmp_path / "Mozilla" / "Firefox" / "Profiles" / "p.default"
    _write(
        prof / "extensions.json",
        {
            "addons": [
                {
                    "id": "amo@x",
                    "type": "extension",
                    "location": "app-profile",
                    "signedState": 2,
                    "sourceURI": "https://addons.mozilla.org/x.xpi",
                    "defaultLocale": {"name": "Good"},
                    "userPermissions": {"permissions": ["storage"], "origins": []},
                },
                {
                    "id": "bad@x",
                    "type": "extension",
                    "location": "app-profile",
                    "signedState": 0,
                    "defaultLocale": {"name": "Bad"},
                    "userPermissions": {"permissions": ["cookies"], "origins": ["<all_urls>"]},
                    "installDate": 1763700000000,
                },
                {"id": "theme", "type": "theme"},
                {"id": "sys", "type": "extension", "location": "app-builtin"},
            ]
        },
    )
    exts = cb.collect_extensions(local=tmp_path / "none", roaming=tmp_path)
    assert [e["name"] for e in exts] == ["Good", "Bad"]
    found = cb.extension_findings(exts)
    assert len(found) == 1 and found[0].name.startswith("Bad")
    assert {"EXT_SIDELOADED", "EXT_UNSIGNED", "EXT_ALL_SITES", "EXT_PERMS"} <= {s.id for s in found[0].signals}


def test_store_extension_without_risky_perms_is_skipped():
    e = {"browser": "Edge", "name": "x", "from_store": True, "permissions": ["storage"], "hosts": []}
    assert cb.extension_findings([e]) == []


def test_engine_dry_run_browsers(tmp_path):
    opts = engine.TriageOptions(browsers=True, dry_run=True, config_dir=tmp_path)
    res = engine.TriageEngine(opts, {}).run()
    found = res.sections[engine.SECTION_BROWSERS]
    names = {f.name for f in found}
    assert "PDF Converter Pro 1.4.2" in names and not any(n.startswith("Google Translate") for n in names)
    pdf = next(f for f in found if f.name.startswith("PDF"))
    assert pdf.status.value == "DETECTADO"
    assert not any(s.id.startswith("PATH_") for s in pdf.signals)  # sin heurísticas de ruta
