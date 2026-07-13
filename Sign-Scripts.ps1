#Requires -Version 5.1
<#
.SYNOPSIS
    Genera hashes SHA256 y (opcionalmente) firma Authenticode los scripts del assessment.
.DESCRIPTION
    Refuerza la confianza de cadena de suministro (supply-chain):
      - SIEMPRE escribe SHA256SUMS.txt con el hash de cada .ps1, template HTML y perfil JSON.
      - Con -Sign firma los .ps1 con un certificado de code-signing (existente o self-signed).
    Los hashes se calculan DESPUES de firmar, asi que SHA256SUMS.txt siempre coincide con
    los archivos publicados.

    Publicacion recomendada: adjuntar SHA256SUMS.txt (y M365Assessment-signing.cer si es
    self-signed) al GitHub Release. Los usuarios verifican integridad antes de ejecutar.
.PARAMETER Sign
    Firma los .ps1 con Authenticode (requiere Windows).
.PARAMETER CreateSelfSigned
    Crea un certificado self-signed de code-signing (uso interno) y firma con el.
    Exporta el .cer publico para que otros lo agreguen a 'Trusted Publishers'.
.PARAMETER Thumbprint
    Thumbprint de un certificado de code-signing ya presente en Cert:\CurrentUser\My.
.PARAMETER TimeStampServer
    Servidor de timestamp RFC3161 (default: DigiCert). El timestamp hace que la firma
    siga siendo valida aunque el certificado expire.
.EXAMPLE
    .\Sign-Scripts.ps1
    # Solo genera SHA256SUMS.txt (sin firmar).
.EXAMPLE
    .\Sign-Scripts.ps1 -Sign -CreateSelfSigned
    # Crea cert self-signed, firma los .ps1, exporta el .cer y genera hashes.
.EXAMPLE
    .\Sign-Scripts.ps1 -Sign -Thumbprint 1A2B3C...
    # Firma con un cert existente (ej. OV/EV de una CA).
.NOTES
    El modo de hashes es local. Con -Sign, el timestamp contacta el servidor
    configurado y envia el resumen criptografico de la firma, no los archivos.
    La firma Authenticode solo aplica en Windows.
#>
param(
    [switch]$Sign,
    [switch]$CreateSelfSigned,
    [string]$Thumbprint,
    [string]$TimeStampServer = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$SelfName  = Split-Path $PSCommandPath -Leaf

# Archivos a proteger: scripts .ps1 (excepto este), template HTML y perfil.
$AllFiles = @(Get-ChildItem -LiteralPath $ScriptDir -File | Where-Object {
    ($_.Extension -eq '.ps1' -or $_.Extension -eq '.html' -or $_.Extension -eq '.js' -or $_.Name -eq 'assessment-profile.json') -and $_.Name -ne $SelfName
} | Sort-Object Name)

if ($AllFiles.Count -eq 0) { Write-Error "No se encontraron .ps1 / .html en $ScriptDir"; return }

# ── Firmar (opcional) ───────────────────────────────────────────────────────
if ($Sign) {
    $OnWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }  # PS 5.1 => Windows
    if (-not $OnWindows) { Write-Error "La firma Authenticode solo esta disponible en Windows. Usa -Sign en Windows, o corre sin -Sign para solo hashes."; return }

    $Cert = $null
    if ($CreateSelfSigned) {
        Write-Host "[*] Creando certificado self-signed de code-signing..." -ForegroundColor Cyan
        $Cert = New-SelfSignedCertificate -Type CodeSigningCert `
            -Subject "CN=M365Assessment (self-signed)" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(3)
        $CerPath = Join-Path $ScriptDir "M365Assessment-signing.cer"
        Export-Certificate -Cert $Cert -FilePath $CerPath | Out-Null
        Write-Host "  [OK] Cert exportado: $CerPath" -ForegroundColor Green
        Write-Host "       Para confiar en otras maquinas: Import-Certificate -FilePath M365Assessment-signing.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher" -ForegroundColor DarkGray
    }
    elseif ($Thumbprint) {
        $Cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
        if (-not $Cert) { Write-Error "No se encontro el cert con thumbprint $Thumbprint en Cert:\CurrentUser\My"; return }
    }
    else {
        $Cert = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $Cert) { Write-Error "No hay certificado de code-signing disponible. Usa -CreateSelfSigned o -Thumbprint."; return }
    }

    Write-Host "[*] Firmando .ps1 con: $($Cert.Subject)" -ForegroundColor Cyan
    foreach ($f in ($AllFiles | Where-Object { $_.Extension -eq '.ps1' })) {
        $r = Set-AuthenticodeSignature -LiteralPath $f.FullName -Certificate $Cert -TimeStampServer $TimeStampServer
        $col = if ($r.Status -eq 'Valid') { 'Green' } else { 'Yellow' }
        Write-Host ("  [{0}] {1}" -f $r.Status, $f.Name) -ForegroundColor $col
    }
}

# ── Hashes SHA256 (siempre, y despues de firmar) ────────────────────────────
Write-Host "[*] Generando SHA256SUMS.txt..." -ForegroundColor Cyan
$Lines = foreach ($f in $AllFiles) {
    $h = Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName
    "{0}  {1}" -f $h.Hash.ToLower(), $f.Name
}
$SumsPath = Join-Path $ScriptDir "SHA256SUMS.txt"
$Lines | Set-Content -LiteralPath $SumsPath -Encoding ascii
Write-Host "[OK] $SumsPath ($($AllFiles.Count) archivos)" -ForegroundColor Green
Write-Host ""
Write-Host "  Verificacion (en otra maquina, antes de ejecutar):" -ForegroundColor Gray
Write-Host "    Get-ChildItem *.ps1,*.html,*.js,assessment-profile.json | Get-FileHash -Algorithm SHA256 | ForEach-Object { `"`$(`$_.Hash.ToLower())  `$(Split-Path `$_.Path -Leaf)`" }" -ForegroundColor DarkGray
Write-Host "    # comparar contra SHA256SUMS.txt publicado en el Release" -ForegroundColor DarkGray
