# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller: dos ejecutables (ventana + consola) que comparten las mismas librerías.

pyinstaller --noconfirm --clean packaging/win11-triage.spec   →   dist/win11-triage/
"""

import os

from PyInstaller.utils.hooks import collect_data_files

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - SPECPATH lo define PyInstaller
PKG = os.path.join(ROOT, "win11_triage")
ICON = os.path.join(PKG, "assets", "icon.ico")
VERSION = os.path.join(SPECPATH, "version_info.txt")  # noqa: F821 - generado por scripts/make_version_info.py

datas = [
    (os.path.join(PKG, "samples"), "win11_triage/samples"),
    (os.path.join(PKG, "assets"), "win11_triage/assets"),
    (os.path.join(PKG, "rules", "yara"), "win11_triage/rules/yara"),
    (os.path.join(PKG, "rules", "sigma"), "win11_triage/rules/sigma"),
    (os.path.join(PKG, "remote"), "win11_triage/remote"),
    *collect_data_files("customtkinter"),
]
excludes = ["matplotlib", "numpy", "pandas", "scipy", "pytest", "IPython"]


def analysis(script):
    return Analysis(  # noqa: F821
        [os.path.join(ROOT, script)],
        pathex=[ROOT],
        datas=datas,
        hiddenimports=["win11_triage.gui.app", "PIL._tkinter_finder"],
        excludes=excludes,
        noarchive=False,
    )


a_gui = analysis("win11-triage-gui.pyw")
a_cli = analysis("win11-triage.py")

exe_gui = EXE(  # noqa: F821
    PYZ(a_gui.pure),  # noqa: F821
    a_gui.scripts,
    [],
    exclude_binaries=True,
    name="win11-triage-gui",
    console=False,
    icon=ICON,
    version=VERSION,
    upx=False,  # UPX dispara falsos positivos en antivirus
)
exe_cli = EXE(  # noqa: F821
    PYZ(a_cli.pure),  # noqa: F821
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name="win11-triage",
    console=True,
    icon=ICON,
    version=VERSION,
    upx=False,
)

coll = COLLECT(  # noqa: F821
    exe_gui,
    a_gui.binaries,
    a_gui.datas,
    exe_cli,
    a_cli.binaries,
    a_cli.datas,
    upx=False,
    name="win11-triage",
)
