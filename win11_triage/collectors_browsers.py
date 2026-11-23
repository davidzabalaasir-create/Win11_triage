"""Extensiones de navegador: Chrome, Edge, Brave (Chromium) y Firefox.

Solo lectura de ficheros del perfil, sin abrir el navegador:
- Chromium: ``<User Data>/<Perfil>/Extensions/<id>/<versión>/manifest.json`` y
  ``Secure Preferences`` / ``Preferences`` (origen de la instalación, fecha, estado).
- Firefox: ``<Profiles>/<perfil>/extensions.json`` (firma, origen, permisos).

Señales: instalada fuera de la tienda, sin empaquetar (modo desarrollador), sin firma (Firefox),
acceso a todos los sitios y permisos sensibles (proxy, debugger, nativeMessaging…).
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Finding, Signal

CHROMIUM = {
    "Chrome": ("Google", "Chrome", "User Data"),
    "Edge": ("Microsoft", "Edge", "User Data"),
    "Brave": ("BraveSoftware", "Brave-Browser", "User Data"),
}
SENSITIVE = {
    "nativeMessaging": "comunicarse con programas del equipo",
    "debugger": "depurar pestañas (leer y modificar todo)",
    "proxy": "cambiar el proxy",
    "management": "gestionar otras extensiones",
    "webRequestBlocking": "interceptar y bloquear peticiones",
    "cookies": "leer cookies",
    "clipboardRead": "leer el portapapeles",
    "desktopCapture": "capturar la pantalla",
    "history": "leer el historial",
    "downloads": "gestionar descargas",
}
ALL_SITES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
# Chromium «location»: 1 tienda/interna, 2 externa (preferencias), 3 externa (registro),
# 4 sin empaquetar, 5 componente, 6 política (externa), 7 política, 8 comando, 9 no empaquetada (comando)
CHROMIUM_LOCATION = {1: "tienda", 2: "externa", 3: "registro", 4: "sin empaquetar", 5: "componente",
                     6: "política", 7: "política", 8: "línea de comandos", 9: "sin empaquetar"}  # fmt: skip
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}


def _msg(manifest: dict[str, Any], ext_dir: Path, value: str) -> str:
    """Resuelve nombres «__MSG_appName__» con _locales/<idioma>/messages.json."""
    if not value.startswith("__MSG_"):
        return value
    key = value[6:].rstrip("_").lower()
    for loc in (manifest.get("default_locale", "en"), "es", "en", "en_US"):
        msgs = _read_json(ext_dir / "_locales" / loc / "messages.json")
        for k, v in msgs.items():
            if k.lower() == key and isinstance(v, dict):
                return str(v.get("message", value))
    return value


def _chrome_time(raw: Any) -> str:
    """install_time de Chromium: microsegundos desde 1601."""
    try:
        return (CHROME_EPOCH + timedelta(microseconds=int(raw))).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return ""


# ------------------------------------------------------------------ recolección
def chromium_extensions(user_data: Path, browser: str) -> list[dict[str, Any]]:
    out = []
    if not user_data.is_dir():
        return out
    for profile in sorted(p for p in user_data.iterdir() if p.is_dir()):
        ext_root = profile / "Extensions"
        if not ext_root.is_dir():
            continue
        prefs: dict[str, Any] = {}
        for name in ("Preferences", "Secure Preferences"):
            prefs.update(_read_json(profile / name).get("extensions", {}).get("settings", {}))
        for ext in sorted(p for p in ext_root.iterdir() if p.is_dir()):
            versions = sorted((v for v in ext.iterdir() if (v / "manifest.json").exists()), key=lambda p: p.name)
            if not versions:
                continue
            vdir = versions[-1]
            man = _read_json(vdir / "manifest.json")
            if not man:
                continue
            st = prefs.get(ext.name, {})
            perms = [p for p in man.get("permissions", []) if isinstance(p, str)]
            hosts = [p for p in man.get("host_permissions", []) if isinstance(p, str)]
            for cs in man.get("content_scripts", []) or []:
                hosts += [m for m in cs.get("matches", []) if isinstance(m, str)]
            location = st.get("location", 1)
            out.append(
                {
                    "browser": browser,
                    "profile": profile.name,
                    "id": ext.name,
                    "name": _msg(man, vdir, str(man.get("name", ext.name))),
                    "version": str(man.get("version", vdir.name)),
                    "path": str(vdir),
                    "permissions": sorted(set(perms)),
                    "hosts": sorted(set(hosts)),
                    "from_store": bool(st.get("from_webstore", location == 1)) and location == 1,
                    "location": CHROMIUM_LOCATION.get(location, str(location)),
                    "unpacked": location in (4, 9),
                    "enabled": st.get("state", 1) == 1 and not st.get("disable_reasons"),
                    "installed": _chrome_time(st.get("first_install_time") or st.get("install_time")),
                    "signed": True,
                    "update_url": str(man.get("update_url", "")),
                }
            )
    return out


def firefox_extensions(profiles_dir: Path) -> list[dict[str, Any]]:
    out = []
    if not profiles_dir.is_dir():
        return out
    for profile in sorted(p for p in profiles_dir.iterdir() if p.is_dir()):
        for a in _read_json(profile / "extensions.json").get("addons", []):
            if a.get("type") != "extension" or a.get("location") in ("app-builtin", "app-system-defaults"):
                continue
            up = a.get("userPermissions") or {}
            installed = a.get("installDate")
            out.append(
                {
                    "browser": "Firefox",
                    "profile": profile.name,
                    "id": a.get("id", ""),
                    "name": (a.get("defaultLocale") or {}).get("name") or a.get("id", ""),
                    "version": a.get("version", ""),
                    "path": a.get("path", ""),
                    "permissions": sorted(p for p in up.get("permissions", []) if isinstance(p, str)),
                    "hosts": sorted(p for p in up.get("origins", []) if isinstance(p, str)),
                    "from_store": str(a.get("sourceURI") or "").startswith("https://addons.mozilla.org/"),
                    "location": a.get("location", ""),
                    "unpacked": a.get("location") == "app-temporary",
                    "enabled": bool(a.get("active", True)),
                    "installed": datetime.fromtimestamp(installed / 1000, timezone.utc).isoformat(timespec="seconds")
                    if isinstance(installed, (int, float))
                    else "",
                    "signed": (a.get("signedState") or 0) > 0,
                    "update_url": "",
                }
            )
    return out


def collect_extensions(local: Path | None = None, roaming: Path | None = None) -> list[dict[str, Any]]:
    local = local or Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    roaming = roaming or Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    exts = []
    for browser, parts in CHROMIUM.items():
        exts += chromium_extensions(local.joinpath(*parts), browser)
    exts += firefox_extensions(roaming / "Mozilla" / "Firefox" / "Profiles")
    return exts


# ------------------------------------------------------------------ señales
def extension_signals(e: dict[str, Any]) -> list[Signal]:
    sigs: list[Signal] = []
    where = f"{e['browser']} · {e.get('location') or '—'}"
    if e.get("unpacked"):
        sigs.append(Signal("EXT_UNPACKED", "Extensión sin empaquetar (modo desarrollador)", 30, "T1176", where))
    elif not e.get("from_store"):
        sigs.append(Signal("EXT_SIDELOADED", "Extensión instalada fuera de la tienda oficial", 30, "T1176", where))
    if e["browser"] == "Firefox" and not e.get("signed"):
        sigs.append(Signal("EXT_UNSIGNED", "Complemento de Firefox sin firma de Mozilla", 25, "T1176", where))
    perms, hosts = set(e.get("permissions", [])), set(e.get("hosts", []))
    if (perms | hosts) & ALL_SITES:
        sigs.append(Signal("EXT_ALL_SITES", "Puede leer y cambiar todos los sitios web", 15, "T1176", "<all_urls>"))
    sensitive = sorted(perms & set(SENSITIVE))
    if sensitive:
        weight = 25 if {"nativeMessaging", "debugger", "proxy", "management"} & set(sensitive) else 10
        sigs.append(
            Signal(
                "EXT_PERMS",
                "Permisos sensibles",
                weight,
                "T1176",
                ", ".join(f"{p} ({SENSITIVE[p]})" for p in sensitive),
            )
        )
    return sigs


def extension_findings(exts: Iterable[dict[str, Any]]) -> list[Finding]:
    out = []
    for e in exts:
        sigs = extension_signals(e)
        if not sigs:
            continue
        f = Finding(
            source="browser",
            name=f"{e['name']} {e.get('version', '')}".strip(),
            path=e.get("path", ""),
            publisher=e["browser"],
            signature="tienda oficial" if e.get("from_store") else "(fuera de la tienda)",
            sha256="",
            category=f"Extensión de {e['browser']}" + ("" if e.get("enabled", True) else " (desactivada)"),
            location=f"{e['browser']} · perfil {e.get('profile', '')} · id {e.get('id', '')}",
            cmdline=", ".join(e.get("permissions", [])[:12]),
            created=e.get("installed", ""),
        )
        f.signals = sigs
        out.append(f)
    return out
