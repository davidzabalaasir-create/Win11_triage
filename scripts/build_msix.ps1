# Empaqueta dist\win11-triage como MSIX (Microsoft Store o instalación local).
#   Para la Store: usa los valores de Partner Center (Producto > Identidad del producto) y sube el
#   .msix sin firmar: la Store lo firma con un certificado de Microsoft (sin avisos de SmartScreen).
#   Para probar en local: -Publisher debe coincidir con el sujeto del certificado de -CertThumbprint.
# Requiere haber ejecutado antes scripts\build_exe.ps1 y el Windows SDK (makeappx.exe, signtool.exe).
# Uso: .\scripts\build_msix.ps1 -IdentityName 12345David.win11-triage -Publisher "CN=XXXX-..." -PublisherDisplay David
param(
    [string] $IdentityName = $env:MSIX_IDENTITY_NAME,
    [string] $Publisher = $env:MSIX_PUBLISHER,
    [string] $PublisherDisplay = "David",
    [string] $CertThumbprint
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $IdentityName) { $IdentityName = "David.win11-triage" }  # solo para pruebas locales
if (-not $Publisher) { $Publisher = "CN=David" }

$version = python -c "import win11_triage; print(win11_triage.__version__)"
$msixVersion = (($version -split '[^0-9]+' | Where-Object { $_ } | Select-Object -First 3) + @('0', '0', '0'))[0..2] -join '.'
$msixVersion = "$msixVersion.0"

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $sdk) { throw "makeappx.exe no encontrado: instala el Windows SDK (winget install Microsoft.WindowsSDK.10.0.26100)" }
$signtool = Join-Path $sdk.DirectoryName "signtool.exe"

python scripts/make_msix_assets.py
$stage = "dist\msix"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "dist\win11-triage" $stage -Recurse
Copy-Item "packaging\msix\Assets" "$stage\Assets" -Recurse
(Get-Content "packaging\msix\AppxManifest.xml" -Raw -Encoding UTF8).
    Replace("{{IDENTITY_NAME}}", $IdentityName).Replace("{{PUBLISHER}}", [Security.SecurityElement]::Escape($Publisher)).
    Replace("{{PUBLISHER_DISPLAY}}", [Security.SecurityElement]::Escape($PublisherDisplay)).
    Replace("{{VERSION}}", $msixVersion) | Set-Content "$stage\AppxManifest.xml" -Encoding UTF8

$out = "dist\win11-triage-$version.msix"
& $sdk.FullName pack /o /d $stage /p $out
if ($LASTEXITCODE) { throw "makeappx falló" }
Remove-Item $stage -Recurse -Force

if ($CertThumbprint) {
    & $signtool sign /fd SHA256 /sha1 $CertThumbprint.Replace(" ", "") /tr http://timestamp.digicert.com /td SHA256 $out
    if ($LASTEXITCODE) { throw "signtool falló (¿-Publisher coincide con el sujeto del certificado?)" }
}
Write-Host "MSIX: $out ($msixVersion, $IdentityName)" -ForegroundColor Green
