<#
.SYNOPSIS
  Firma win11-triage con tu certificado de Certum (SimplySign) y genera el instalador firmado.

.DESCRIPTION
  El Control de aplicaciones inteligente (Smart App Control) de Windows 11 bloquea ejecutables
  sin firma. Este script toma la versión portable que compila GitHub Actions y:
    1. Firma todos los .exe/.dll/.pyd sin firma con tu certificado (con sello de tiempo de Certum).
    2. Reconstruye el instalador con Inno Setup y lo firma.
    3. Vuelve a empaquetar la versión portable ya firmada.

  No necesita Python ni el SDK de Windows: usa Set-AuthenticodeSignature de PowerShell.

.REQUISITOS
  - SimplySign Desktop abierto y conectado (el certificado aparece en el almacén de Windows).
  - Inno Setup 6:  winget install --id JRSoftware.InnoSetup -e
  - Este repositorio clonado (el script usa packaging\installer.iss).

.EXAMPLE
  # 1. Descarga win11-triage-portable-<versión>.zip de la release de GitHub.
  # 2. Desde la carpeta del repositorio:
  powershell -ExecutionPolicy Bypass -File scripts\sign_release.ps1 -Portable "$HOME\Downloads\win11-triage-portable-2.0.0.zip"

.EXAMPLE
  # Si tienes varios certificados de firma, indica la huella (Thumbprint) del de Certum:
  powershell -ExecutionPolicy Bypass -File scripts\sign_release.ps1 -Portable ...zip -Thumbprint 0123ABCD...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Portable,
    [string] $Thumbprint,
    [string] $TimestampServer = "http://time.certum.pl",
    [string] $OutDir = "dist-signed"
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

function Write-Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

# ------------------------------------------------------------------ certificado
Write-Step "Buscando el certificado de firma de código"
$certs = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) })
if ($Thumbprint) { $certs = @($certs | Where-Object { $_.Thumbprint -eq $Thumbprint.Replace(" ", "").ToUpper() }) }
if ($certs.Count -eq 0) {
    throw "No hay ningún certificado de firma válido. ¿Está SimplySign Desktop abierto y conectado?"
}
if ($certs.Count -gt 1) {
    $certs | Format-Table Thumbprint, Subject, NotAfter -AutoSize | Out-Host
    throw "Hay varios certificados: repite con -Thumbprint <huella> para elegir el de Certum."
}
$cert = $certs[0]
Write-Host "Certificado: $($cert.Subject)  (caduca $($cert.NotAfter.ToString('d')))"

function Sign-File([string] $path) {
    $sig = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256 `
        -TimestampServer $TimestampServer -IncludeChain NotRoot
    if ($sig.Status -ne "Valid") { throw "No se pudo firmar $path : $($sig.StatusMessage)" }
}

# ------------------------------------------------------------------ preparar
Write-Step "Extrayendo la versión portable"
if (-not (Test-Path $Portable)) { throw "No existe $Portable" }
$version = [regex]::Match((Split-Path $Portable -Leaf), "\d+\.\d+\.\d+").Value
if (-not $version) { $version = python -c "import win11_triage; print(win11_triage.__version__)" 2>$null }
if (-not $version) { throw "No se pudo deducir la versión del nombre del zip." }

$work = Join-Path $root "dist\win11-triage"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $work | Out-Null
Expand-Archive -Path $Portable -DestinationPath $work -Force
Remove-Item (Join-Path $work "portable.txt") -ErrorAction SilentlyContinue  # el instalador no es portable
Remove-Item (Join-Path $work ".env.example") -ErrorAction SilentlyContinue

# ------------------------------------------------------------------ firmar binarios
Write-Step "Firmando ejecutables y bibliotecas sin firma (puede pedir confirmación en SimplySign)"
$binaries = Get-ChildItem $work -Recurse -Include *.exe, *.dll, *.pyd
$toSign = $binaries | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" }
Write-Host "$($binaries.Count) binarios, $($toSign.Count) sin firma válida."
$i = 0
foreach ($f in $toSign) {
    $i++
    Write-Progress -Activity "Firmando" -Status $f.Name -PercentComplete (100 * $i / $toSign.Count)
    Sign-File $f.FullName
}
Write-Progress -Activity "Firmando" -Completed

# ------------------------------------------------------------------ instalador
Write-Step "Construyendo el instalador con Inno Setup"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 no está instalado:  winget install --id JRSoftware.InnoSetup -e" }
& $iscc "/DAppVersion=$version" packaging\installer.iss | Out-Host
if ($LASTEXITCODE) { throw "Inno Setup falló." }
$setup = Join-Path $root "dist\win11-triage-setup-$version.exe"
Sign-File $setup

# ------------------------------------------------------------------ portable firmada
Write-Step "Empaquetando la versión portable firmada"
"Modo portable: la configuración y los informes se guardan en esta carpeta." | Set-Content (Join-Path $work "portable.txt")
Copy-Item ".env.example" $work
New-Item -ItemType Directory -Force $OutDir | Out-Null
$zip = Join-Path $OutDir "win11-triage-portable-$version.zip"
Compress-Archive -Path "$work\*" -DestinationPath $zip -Force
Move-Item $setup (Join-Path $OutDir (Split-Path $setup -Leaf)) -Force

# ------------------------------------------------------------------ verificación
Write-Step "Verificando firmas"
$check = Join-Path $OutDir "win11-triage-setup-$version.exe"
$s = Get-AuthenticodeSignature $check
Write-Host "$(Split-Path $check -Leaf): $($s.Status) — $($s.SignerCertificate.Subject)"
if ($s.Status -ne "Valid") { throw "La firma del instalador no es válida." }
Get-ChildItem $OutDir | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
} | Tee-Object (Join-Path $OutDir "SHA256SUMS.txt")

Write-Host "`nListo. Sube el contenido de '$OutDir' a la release de GitHub (sustituyendo los archivos sin firmar)." -ForegroundColor Green
