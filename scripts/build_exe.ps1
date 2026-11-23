# Compila la aplicación de Windows:
#   dist\win11-triage\                      carpeta con win11-triage-gui.exe y win11-triage.exe
#   dist\win11-triage-setup-<versión>.exe   instalador (Inno Setup 6)
#   dist\win11-triage-<versión>.msi         instalador MSI (WiX Toolset v5: dotnet tool install -g wix)
#   dist\win11-triage-portable-<versión>.zip
# Con -CertThumbprint firma todos los binarios propios, el instalador y el MSI.
# Uso: powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 [-CertThumbprint <huella>]
param(
    [string] $CertThumbprint,
    [string] $TimestampServer = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$cert = $null
if ($CertThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Thumbprint -eq $CertThumbprint.Replace(" ", "").ToUpper() } | Select-Object -First 1
    if (-not $cert) { throw "No se encontró el certificado $CertThumbprint en Cert:\CurrentUser\My" }
    Write-Host "Firmando como: $($cert.Subject)" -ForegroundColor Cyan
}

function Sign-File([string] $path) {
    if (-not $cert) { return }
    $sig = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256 `
        -TimestampServer $TimestampServer -IncludeChain NotRoot
    if (-not $sig.SignerCertificate) { throw "No se pudo firmar $path : $($sig.StatusMessage)" }
}

python -m pip install -e ".[build,yara]"
python scripts/make_version_info.py
python scripts/make_license_rtf.py
$version = python -c "import win11_triage; print(win11_triage.__version__)"

pyinstaller --noconfirm --clean packaging/win11-triage.spec
if ($LASTEXITCODE) { throw "PyInstaller falló" }

if ($cert) {
    # Se firma antes de empaquetar, para que el instalador, el MSI y el zip lleven binarios firmados.
    $bins = Get-ChildItem dist\win11-triage -Recurse -Include *.exe, *.dll, *.pyd |
        Where-Object { -not (Get-AuthenticodeSignature $_.FullName).SignerCertificate }
    Write-Host "Firmando $($bins.Count) binarios sin firma…"
    foreach ($b in $bins) { Sign-File $b.FullName }
}

# Versión portable: portable.txt hace que la configuración se guarde junto al .exe.
$portable = "dist\portable"
Remove-Item $portable -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "dist\win11-triage" $portable -Recurse
"Modo portable: la configuración y los informes se guardan en esta carpeta." | Set-Content "$portable\portable.txt"
Copy-Item ".env.example" $portable
Compress-Archive -Path "$portable\*" -DestinationPath "dist\win11-triage-portable-$version.zip" -Force
Remove-Item $portable -Recurse -Force

# Instalador .exe (Inno Setup)
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc "/DAppVersion=$version" packaging\installer.iss
    if ($LASTEXITCODE) { throw "Inno Setup falló" }
    Sign-File "dist\win11-triage-setup-$version.exe"
} else {
    Write-Warning "Inno Setup 6 no encontrado: se omite el instalador .exe (winget install JRSoftware.InnoSetup)."
}

# Instalador .msi (WiX)
if (Get-Command wix -ErrorAction SilentlyContinue) {
    wix build packaging\win11-triage.wxs -arch x64 -ext WixToolset.UI.wixext `
        -d "Version=$version" -bindpath "app=dist\win11-triage" -o "dist\win11-triage-$version.msi"
    if ($LASTEXITCODE) { throw "WiX falló" }
    Remove-Item "dist\win11-triage-$version.wixpdb" -ErrorAction SilentlyContinue
    Sign-File "dist\win11-triage-$version.msi"
} else {
    Write-Warning "WiX no encontrado: se omite el .msi (dotnet tool install -g wix --version 5.0.2)."
}

Write-Host "Listo: dist\" -ForegroundColor Green
Get-ChildItem dist -File | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
    [pscustomobject]@{ Archivo = $_.Name; MB = [math]::Round($_.Length / 1MB, 1)
                       Firma = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { "-" } }
} | Format-Table -AutoSize
