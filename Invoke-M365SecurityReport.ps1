#Requires -Version 5.1
<#
.SYNOPSIS
    Orquestador interactivo de M365 Security Assessment.
.DESCRIPTION
    Coordina la ejecucion de los 3 scripts de recoleccion de datos y genera
    el reporte HTML final. Detecta archivos existentes y sugiere omitir modulos.
.PARAMETER OutputPath
    Carpeta donde se guardan JSON/CSV y el HTML final. Default: .\output
.PARAMETER InactiveDays
    Dias de inactividad para clasificar usuarios inactivos. Default: 90
.PARAMETER All
    Ejecuta todos los modulos sin interaccion (modo CI/CD).
.PARAMETER ReportOnly
    Solo genera el reporte HTML a partir de archivos existentes (sin recoleccion).
.PARAMETER Open
    Abre el reporte HTML al finalizar.
.EXAMPLE
    .\Invoke-M365SecurityReport.ps1
.EXAMPLE
    .\Invoke-M365SecurityReport.ps1 -All -OutputPath "C:\Reports"
.EXAMPLE
    .\Invoke-M365SecurityReport.ps1 -ReportOnly
#>
param(
    [string]$OutputPath   = ".\output",
    [int]$InactiveDays    = 90,
    [switch]$All,
    [switch]$ReportOnly,
    [switch]$Open
)
$ErrorActionPreference = "Continue"  # No abortar si un modulo falla

# ============================================================================
# COLORES Y HELPERS
# ============================================================================
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       M365 Security Assessment  —  Orquestador v2.0      ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Step([string]$Msg, [string]$Color = "Yellow") {
    Write-Host "  $(Get-Date -Format 'HH:mm:ss')  $Msg" -ForegroundColor $Color
}
function Elapsed([datetime]$Start) { "{0:mm\:ss}" -f ([datetime]::Now - $Start) }
function Find-Latest([string]$Dir, [string]$Filter) {
    Get-ChildItem $Dir -Filter $Filter -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
function Ask-YesNo([string]$Question, [bool]$Default = $true) {
    $opts = if ($Default) { "[Y/n]" } else { "[y/N]" }
    Write-Host "  $Question $opts " -ForegroundColor White -NoNewline
    $r = Read-Host
    if ($r -eq "") { return $Default }
    return $r -match '^[YySs]'
}

# ============================================================================
# VALIDAR MODULOS DE MICROSOFT GRAPH
# ============================================================================
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Users"
)

$MissingModules = @()
foreach ($mod in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -EA SilentlyContinue)) {
        $MissingModules += $mod
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Banner
    Write-Host "  [!] Modulos de Microsoft Graph no encontrados:" -ForegroundColor Red
    Write-Host ""
    foreach ($m in $MissingModules) {
        Write-Host "      - $m" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Se requieren para consultar licencias, usuarios y seguridad de M365." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Instalar ahora? [Y/n]: " -ForegroundColor White -NoNewline
    $installResp = (Read-Host).Trim()
    if ($installResp -eq "" -or $installResp -match '^[YySs]') {
        Write-Host ""
        Write-Step "Instalando modulos (esto puede tardar 1-3 minutos)..." "Cyan"
        foreach ($m in $MissingModules) {
            Write-Step "  Instalando $m..." "Yellow"
            try {
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
                Write-Step "  [OK] $m instalado" "Green"
            } catch {
                Write-Step "  [ERROR] No se pudo instalar ${m}: $_" "Red"
                Write-Host ""
                Write-Host "  Puedes instalarlo manualmente:" -ForegroundColor Yellow
                Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
                Write-Host ""
                exit 1
            }
        }
        Write-Host ""
        Write-Step "Todos los modulos instalados correctamente" "Green"
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "  Para instalar manualmente ejecuta:" -ForegroundColor Yellow
        Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
        Write-Host ""
        exit 0
    }
}

# Importar modulos
foreach ($mod in $RequiredModules) {
    Import-Module $mod -ErrorAction SilentlyContinue
}

# ============================================================================
# VALIDAR QUE LOS SCRIPTS EXISTAN
# ============================================================================
$ScriptDir   = $PSScriptRoot
$ScriptLic   = Join-Path $ScriptDir "Get-M365LicensingData.ps1"
$ScriptAdopt = Join-Path $ScriptDir "Get-M365SecurityAdoption.ps1"
$ScriptScore = Join-Path $ScriptDir "Get-M365SecureScore.ps1"
$ScriptInj   = Join-Path $ScriptDir "New-M365Report.ps1"
$Template    = Join-Path $ScriptDir "report-template.html"

foreach ($S in @($ScriptLic, $ScriptAdopt, $ScriptScore, $ScriptInj, $Template)) {
    if (-not (Test-Path $S)) { Write-Error "Archivo requerido no encontrado: $S" }
}

# Crear carpeta de salida si no existe
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path

# ============================================================================
# DETECTAR ARCHIVOS EXISTENTES
# ============================================================================
$ExistLic    = Find-Latest $OutputPath "*_report_data.json"
$ExistUsers  = Find-Latest $OutputPath "*_02_Users.csv"
$ExistAdopt  = Find-Latest $OutputPath "*_security_adoption.json"
$ExistScore  = Find-Latest $OutputPath "*_secure_score.json"

function File-Age([object]$FileInfo) {
    if (-not $FileInfo) { return "" }
    $age = ((Get-Date) - $FileInfo.LastWriteTime).TotalHours
    if ($age -lt 1) { return " (hace $([int]($age*60))min)" }
    if ($age -lt 24) { return " (hace $([int]$age)h)" }
    return " (hace $([int]($age/24))d)"
}

# ============================================================================
# MODO REPORT-ONLY
# ============================================================================
if ($ReportOnly) {
    Write-Banner
    Write-Step "Modo ReportOnly — generando HTML a partir de archivos existentes..." "Cyan"
    if (-not $ExistLic) { Write-Error "No se encontro _report_data.json en $OutputPath" }
    & $ScriptInj -OutputPath $OutputPath -TemplatePath $Template -Open:$Open
    exit
}

# ============================================================================
# MENU INTERACTIVO (a menos que -All)
# ============================================================================
if (-not $All) {
    Write-Banner

    Write-Host "  Carpeta de salida: $OutputPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Modulos disponibles:" -ForegroundColor White
    Write-Host ""

    # Lic
    $LicStatus = if ($ExistLic) { "[Existe$(File-Age $ExistLic)] $($ExistLic.Name)" } else { "[No encontrado]" }
    Write-Host "  1. Licenciamiento & Usuarios    $LicStatus" -ForegroundColor $(if ($ExistLic) { "DarkGray" } else { "Yellow" })

    # Adoption
    $AdoptStatus = if ($ExistAdopt) { "[Existe$(File-Age $ExistAdopt)] $($ExistAdopt.Name)" } else { "[No encontrado]" }
    Write-Host "  2. Security Adoption (MFA, CA)  $AdoptStatus" -ForegroundColor $(if ($ExistAdopt) { "DarkGray" } else { "Yellow" })

    # Score
    $ScoreStatus = if ($ExistScore) { "[Existe$(File-Age $ExistScore)] $($ExistScore.Name)" } else { "[No encontrado]" }
    Write-Host "  3. Secure Score                 $ScoreStatus" -ForegroundColor $(if ($ExistScore) { "DarkGray" } else { "Yellow" })

    Write-Host ""
    Write-Host "  Opciones:" -ForegroundColor White
    Write-Host "    [A] Ejecutar todos los modulos" -ForegroundColor Cyan
    Write-Host "    [S] Saltar modulos con datos recientes y generar reporte" -ForegroundColor Green
    Write-Host "    [R] Solo generar reporte HTML (sin recoleccion)" -ForegroundColor Yellow
    Write-Host "    [Q] Salir" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Seleccion [A/S/R/Q]: " -ForegroundColor White -NoNewline
    $selection = (Read-Host).Trim().ToUpper()

    switch ($selection) {
        "Q" { Write-Host "Cancelado." -ForegroundColor Red; exit 0 }
        "R" {
            Write-Step "Generando reporte HTML..."
            & $ScriptInj -OutputPath $OutputPath -TemplatePath $Template -Open:$Open
            exit
        }
        "S" {
            # Preguntar por cada modulo que ya tiene datos recientes
            if ($ExistLic -and $ExistLic.LastWriteTime -gt (Get-Date).AddHours(-12)) {
                $RunLic = Ask-YesNo "  Licenciamiento tiene datos de $(File-Age $ExistLic). Re-ejecutar?" $false
            } else { $RunLic = $true }
            if ($ExistAdopt -and $ExistAdopt.LastWriteTime -gt (Get-Date).AddHours(-12)) {
                $RunAdopt = Ask-YesNo "  Adoption tiene datos de $(File-Age $ExistAdopt). Re-ejecutar?" $false
            } else { $RunAdopt = $true }
            if ($ExistScore -and $ExistScore.LastWriteTime -gt (Get-Date).AddHours(-12)) {
                $RunScore = Ask-YesNo "  SecureScore tiene datos de $(File-Age $ExistScore). Re-ejecutar?" $false
            } else { $RunScore = $true }
        }
        default {
            # "A" o cualquier cosa — ejecutar todos
            $RunLic = $true; $RunAdopt = $true; $RunScore = $true
        }
    }
} else {
    # -All sin menu interactivo
    $RunLic   = $true
    $RunAdopt = $true
    $RunScore = $true
}

Write-Step "Iniciando recoleccion de datos..." "Cyan"
Write-Host ""
$GlobalStart = Get-Date
$Results = @{ Lic=$null; Adopt=$null; Score=$null; Report=$null }

# ============================================================================
# CONEXION UNICA A MICROSOFT GRAPH (evita multiples prompts WAM)
# ============================================================================
$NeedGraph = $RunLic -or $RunAdopt -or $RunScore
if ($NeedGraph) {
    Write-Step "Conectando a Microsoft Graph (sesion unica)..." "Cyan"
    $AllScopes = @(
        # Licensing
        "Directory.Read.All", "Organization.Read.All", "User.Read.All", "AuditLog.Read.All",
        # Security Adoption
        "Policy.Read.All", "UserAuthenticationMethod.Read.All", "Reports.Read.All",
        "RoleManagement.Read.All", "IdentityRiskyUser.Read.All",
        "DeviceManagementManagedDevices.Read.All", "ThreatHunting.Read.All",
        # Secure Score
        "SecurityEvents.Read.All"
    )
    try {
        Connect-MgGraph -Scopes $AllScopes -NoWelcome -ErrorAction Stop
        $Ctx = Get-MgContext
        Write-Step "  [OK] Conectado como: $($Ctx.Account) | Tenant: $($Ctx.TenantId)" "Green"
        Write-Host ""
    } catch {
        Write-Step "  [ERROR] No se pudo autenticar: $_" "Red"
        exit 1
    }
}

# ============================================================================
# MODULO 1: LICENCIAMIENTO
# ============================================================================
if ($RunLic) {
    Write-Step "[1/3] Ejecutando Get-M365LicensingData.ps1..." "Yellow"
    $T = Get-Date
    try {
        & $ScriptLic -OutputPath $OutputPath -InactiveDays $InactiveDays
        $Results.Lic = "OK ($(Elapsed $T))"
        Write-Step "  [OK] Licenciamiento completado en $(Elapsed $T)" "Green"
        $ExistLic   = Find-Latest $OutputPath "*_report_data.json"
        $ExistUsers = Find-Latest $OutputPath "*_02_Users.csv"
    } catch {
        $Results.Lic = "ERROR: $_"
        Write-Step "  [WARN] Error en Licenciamiento: $_" "Red"
        if (-not $ExistLic) { Write-Step "  [CRIT] Sin datos de licenciamiento — abortando." "Red"; exit 1 }
        Write-Step "  Usando datos existentes: $($ExistLic.Name)" "Yellow"
    }
} else {
    Write-Step "[1/3] Licenciamiento: omitido (usando $($ExistLic.Name))" "DarkGray"
    $Results.Lic = "SKIP"
}
Write-Host ""

# ============================================================================
# MODULO 2 & 3: ADOPTION + SECURE SCORE (secuencial)
# ============================================================================

if ($RunAdopt) {
    Write-Step "[2/3] Ejecutando Get-M365SecurityAdoption.ps1..." "Yellow"
    $T = Get-Date
    try {
        & $ScriptAdopt -OutputPath $OutputPath
        $Results.Adopt = "OK ($(Elapsed $T))"
        Write-Step "  [OK] Adoption completado en $(Elapsed $T)" "Green"
        $ExistAdopt = Find-Latest $OutputPath "*_security_adoption.json"
    } catch {
        $Results.Adopt = "ERROR: $_"
        Write-Step "  [WARN] Error en Adoption: $_" "Red"
    }
} else {
    Write-Step "[2/3] Adoption: omitido (usando $($ExistAdopt.Name))" "DarkGray"
    $Results.Adopt = "SKIP"
}
Write-Host ""

if ($RunScore) {
    Write-Step "[3/3] Ejecutando Get-M365SecureScore.ps1..." "Yellow"
    $T = Get-Date
    try {
        & $ScriptScore -OutputPath $OutputPath
        $Results.Score = "OK ($(Elapsed $T))"
        Write-Step "  [OK] SecureScore completado en $(Elapsed $T)" "Green"
        $ExistScore = Find-Latest $OutputPath "*_secure_score.json"
    } catch {
        $Results.Score = "ERROR: $_"
        Write-Step "  [WARN] Error en SecureScore: $_" "Red"
    }
} else {
    Write-Step "[3/3] SecureScore: omitido (usando $($ExistScore.Name))" "DarkGray"
    $Results.Score = "SKIP"
}
Write-Host ""

# ============================================================================
# GENERAR REPORTE HTML
# ============================================================================
Write-Step "[HTML] Generando reporte final..." "Cyan"
$T = Get-Date
try {
    $reportFile = & $ScriptInj `
        -OutputPath   $OutputPath `
        -TemplatePath $Template `
        -Open:$Open

    $Results.Report = "OK ($(Elapsed $T)) — $reportFile"
    Write-Step "  [OK] Reporte generado en $(Elapsed $T)" "Green"
} catch {
    $Results.Report = "ERROR: $_"
    Write-Step "  [ERROR] Fallo generando reporte: $_" "Red"
}

# ============================================================================
# RESUMEN
# ============================================================================
Write-Host ""
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Resumen de ejecucion   Total: $(Elapsed $GlobalStart)" -ForegroundColor Cyan
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
$statusColor = @{ "OK"="Green"; "SKIP"="DarkGray"; "ERROR"="Red" }
foreach ($k in @("Lic","Adopt","Score","Report")) {
    $v = $Results[$k]
    if (-not $v) { $v = "N/A" }
    $col = foreach ($key in $statusColor.Keys) { if ($v.StartsWith($key)) { $statusColor[$key]; break } }
    if (-not $col) { $col = "White" }
    Write-Host ("  {0,-12} {1}" -f $k, $v) -ForegroundColor $col
}
Write-Host ""
if ($Results.Report -like "OK*") {
    Write-Host "  Para abrir el reporte en cualquier momento:" -ForegroundColor Gray
    $rFile = Find-Latest $OutputPath "*_M365_Security_Report.html"
    if ($rFile) { Write-Host "  Start-Process '$($rFile.FullName)'" -ForegroundColor Gray }
}

# Cerrar sesion de Graph
if ($NeedGraph) {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Step "Sesion de Microsoft Graph cerrada" "DarkGray"
}
Write-Host ""
