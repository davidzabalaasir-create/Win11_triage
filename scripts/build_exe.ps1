# Compila la aplicación de Windows:
#   dist\win11-triage\                     (carpeta con win11-triage-gui.exe y win11-triage.exe)
#   dist\win11-triage-setup-<versión>.exe  (instalador, si Inno Setup 6 está instalado)
#   dist\win11-triage-portable-<versión>.zip
# Uso: powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

python -m pip install -e ".[build,yara]"
python scripts/make_version_info.py
$version = python -c "import win11_triage; print(win11_triage.__version__)"

pyinstaller --noconfirm --clean packaging/win11-triage.spec
if ($LASTEXITCODE) { throw "PyInstaller falló" }

# Versión portable: portable.txt hace que la configuración se guarde junto al .exe.
$portable = "dist\portable"
Remove-Item $portable -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "dist\win11-triage" $portable -Recurse
"Modo portable: la configuración y los informes se guardan en esta carpeta." | Set-Content "$portable\portable.txt"
Copy-Item ".env.example" $portable
Compress-Archive -Path "$portable\*" -DestinationPath "dist\win11-triage-portable-$version.zip" -Force
Remove-Item $portable -Recurse -Force

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc "/DAppVersion=$version" packaging\installer.iss
    if ($LASTEXITCODE) { throw "Inno Setup falló" }
} else {
    Write-Warning "Inno Setup 6 no encontrado: se omite el instalador (choco install innosetup)."
}
Write-Host "Listo: dist\" -ForegroundColor Green
Get-ChildItem dist -File | Format-Table Name, Length
