<#
.SYNOPSIS
  Crea tu certificado de firma de código «David» (autofirmado) para firmar win11-triage.

.DESCRIPTION
  Se ejecuta UNA vez, en tu PC. La clave privada se queda contigo:
    - Crea el certificado en tu almacén personal (CN=David, válido 5 años, RSA 3072, SHA-256).
    - Exporta win11-triage-signing.pfx (con contraseña) y win11-triage-david.cer (solo la parte pública).
    - Copia al portapapeles el PFX en Base64 para guardarlo como secreto de GitHub.
    - Con -Trust, añade el certificado a «Entidades raíz de confianza» y «Editores de confianza»
      de TU usuario, para que Windows muestre «David» como editor verificado en este PC.

  IMPORTANTE: un certificado autofirmado NO evita el Control de aplicaciones inteligente
  (Smart App Control) ni SmartScreen en otros equipos. Para eso hace falta un certificado de
  una entidad reconocida (SignPath Foundation, gratuito, ya solicitado).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\new_signing_cert.ps1 -Trust
#>
[CmdletBinding()]
param(
    [string] $Name = "David",
    [int] $Years = 5,
    [string] $OutDir = "$HOME\win11-triage-firma",
    [switch] $Trust,
    [switch] $Quiet  # no muestra la contraseña ni usa el portapapeles (CI)
)
$ErrorActionPreference = "Stop"

$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$Name" `
    -FriendlyName "win11-triage ($Name)" -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears($Years)
Write-Host "Certificado creado: $($cert.Subject)  huella $($cert.Thumbprint)" -ForegroundColor Green

New-Item -ItemType Directory -Force $OutDir | Out-Null
$chars = (48..57) + (65..90) + (97..122)
$plain = -join (1..28 | ForEach-Object { [char]($chars | Get-Random) })
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
$pfx = Join-Path $OutDir "win11-triage-signing.pfx"
$cer = Join-Path $OutDir "win11-triage-david.cer"
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
if (-not $Quiet) {
    try { [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx)) | Set-Clipboard }
    catch { Write-Warning "No se pudo copiar al portapapeles: usa  [Convert]::ToBase64String([IO.File]::ReadAllBytes('$pfx'))" }
}

if ($Trust) {
    foreach ($store in "Root", "TrustedPublisher") {
        Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\CurrentUser\$store" | Out-Null
    }
    Write-Host "Certificado marcado como de confianza para tu usuario (Windows puede pedir confirmación)."
}

if ($Quiet) { $cert; return }

Write-Host @"

Listo. Archivos en $OutDir
  - win11-triage-signing.pfx  -> CLAVE PRIVADA: guárdala en un sitio seguro y no la compartas.
  - win11-triage-david.cer    -> parte pública (se puede compartir).

Ahora, en GitHub: Settings -> Secrets and variables -> Actions -> New repository secret
  1. Nombre: WIN11_TRIAGE_PFX           Valor: pega el portapapeles (Ctrl+V, ya copiado)
  2. Nombre: WIN11_TRIAGE_PFX_PASSWORD  Valor: $plain

Desde ese momento, cada compilación firmará los .exe, el instalador y el .msi como "$Name".
"@
