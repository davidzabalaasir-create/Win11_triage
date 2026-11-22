# Genera dist\win11-triage-gui.exe (interfaz) y dist\win11-triage.exe (consola).
# Uso: powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
$ErrorActionPreference = "Stop"
python -m pip install -e ".[build]"

$common = @("--noconfirm", "--onefile", "--clean",
            "--add-data", "win11_triage/samples;win11_triage/samples",
            "--add-data", "win11_triage/assets;win11_triage/assets",
            "--icon", "win11_triage/assets/icon.ico",
            "--collect-data", "customtkinter")

pyinstaller @common --windowed --name win11-triage-gui win11-triage-gui.pyw
pyinstaller @common --console  --name win11-triage     win11-triage.py

Write-Host "Ejecutables en .\dist" -ForegroundColor Green
