#Requires -Version 5.1
<#
.SYNOPSIS
    Orquestador interactivo de M365 Security Assessment.
.DESCRIPTION
    Coordina la ejecucion de los 3 scripts de recoleccion de datos y genera
    el reporte HTML final. Detecta archivos existentes y sugiere omitir modulos.
.PARAMETER OutputPath
    Carpeta donde se guardan JSON/CSV y el HTML final. Default: .\output
.PARAMETER TenantId
    Tenant explicito para la sesion Graph y los collectors.
.PARAMETER DeviceStaleDays
    Dias sin check-in para clasificar un dispositivo Intune como stale.
.PARAMETER RunId
    Prefijo estable para todos los artefactos de una corrida.
.PARAMETER ProfilePath
    Perfil versionado con umbrales y catálogo de controles.
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
    [string]$TenantId,
    [string]$ProfilePath = "$PSScriptRoot/assessment-profile.json",
    [ValidateRange(1, 365)]
    [int]$DeviceStaleDays = 30,
    [ValidateRange(1, 90)]
    [int]$HuntingLookbackDays = 14,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,
    [switch]$All,
    [switch]$ReportOnly,
    [switch]$Open,
    [switch]$KeepIntermediates,
    [ValidateSet("Shareable", "Internal")]
    [string]$PrivacyProfile = "Shareable",
    [switch]$AllowMixedSources,
    [switch]$AllowLegacySchema,
    # Reportes HTML historicos a conservar en output/ (los mas viejos van a la
    # Papelera al final de cada corrida). 0 = conservar todo.
    [ValidateRange(0, 100)]
    [int]$RetentionRuns = 5
)
$ErrorActionPreference = "Continue"  # No abortar si un modulo falla
$RunIdProvided = -not [string]::IsNullOrWhiteSpace($RunId)
$RunId = if ($RunId) { $RunId } else { "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$([guid]::NewGuid().ToString('N').Substring(0,6))" }

# ============================================================================
# COLORES Y HELPERS
# ============================================================================
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       M365 Security Assessment  —  Orquestador v4.2      ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}
function Write-ImportantNotice {
    Write-Host "  Avisos importantes:" -ForegroundColor Yellow
    Write-Host "    - Este proyecto es comunitario y no es una herramienta oficial de Microsoft." -ForegroundColor DarkYellow
    Write-Host "    - La salida puede incluir datos sensibles del tenant; se recomienda eliminar los artefactos generados cuando el reporte ya no sea necesario, segun la politica del cliente." -ForegroundColor DarkYellow
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
    "Microsoft.Graph.Identity.DirectoryManagement"
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

foreach ($S in @($ScriptLic, $ScriptAdopt, $ScriptScore, $ScriptInj, $Template, $ProfilePath)) {
    if (-not (Test-Path $S)) { Write-Error "Archivo requerido no encontrado: $S" }
}

# Crear carpeta de salida si no existe
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path
$OnWindowsHost = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }
if (-not $OnWindowsHost) { & /bin/chmod 700 $OutputPath }

# ============================================================================
# DETECTAR ARCHIVOS EXISTENTES
# ============================================================================
$ExistLic    = Find-Latest $OutputPath "*_report_data.json"
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
    Write-ImportantNotice
    Write-Step "Modo ReportOnly — generando HTML a partir de archivos existentes..." "Cyan"
    if (-not $ExistLic) { Write-Error "No se encontro _report_data.json en $OutputPath" }
    $ReportOnlyParams = @{ OutputPath = $OutputPath; TemplatePath = $Template; ProfilePath = $ProfilePath; Open = $Open; KeepIntermediates = $KeepIntermediates; RetentionRuns = $RetentionRuns; PrivacyProfile = $PrivacyProfile; AllowMixedSources = $AllowMixedSources; AllowLegacySchema = $AllowLegacySchema }
    if ($RunIdProvided) { $ReportOnlyParams.RunId = $RunId }
    & $ScriptInj @ReportOnlyParams
    exit
}

# ============================================================================
# MENU INTERACTIVO (a menos que -All)
# ============================================================================
if (-not $All) {
    Write-Banner
    Write-ImportantNotice

    Write-Host "  Carpeta de salida: $OutputPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Modulos disponibles:" -ForegroundColor White
    Write-Host ""

    # Lic
    $LicStatus = if ($ExistLic) { "[Existe$(File-Age $ExistLic)] $($ExistLic.Name)" } else { "[No encontrado]" }
    Write-Host "  1. Licenciamiento agregado      $LicStatus" -ForegroundColor $(if ($ExistLic) { "DarkGray" } else { "Yellow" })

    # Adoption
    $AdoptStatus = if ($ExistAdopt) { "[Existe$(File-Age $ExistAdopt)] $($ExistAdopt.Name)" } else { "[No encontrado]" }
    Write-Host "  2. Security Adoption (MFA, CA)  $AdoptStatus" -ForegroundColor $(if ($ExistAdopt) { "DarkGray" } else { "Yellow" })

    # Score
    $ScoreStatus = if ($ExistScore) { "[Existe$(File-Age $ExistScore)] $($ExistScore.Name)" } else { "[No encontrado]" }
    Write-Host "  3. Secure Score                 $ScoreStatus" -ForegroundColor $(if ($ExistScore) { "DarkGray" } else { "Yellow" })

    Write-Host ""
    Write-Host "  Opciones:" -ForegroundColor White
    Write-Host "    [A] Ejecutar todos los modulos" -ForegroundColor Cyan
    Write-Host "    [R] Solo generar reporte HTML (sin recoleccion)" -ForegroundColor Yellow
    Write-Host "    [Q] Salir" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Seleccion [A/R/Q]: " -ForegroundColor White -NoNewline
    $selection = (Read-Host).Trim().ToUpper()

    switch ($selection) {
        "Q" { Write-Host "Cancelado." -ForegroundColor Red; exit 0 }
        "R" {
            Write-Step "Generando reporte HTML..."
            & $ScriptInj -OutputPath $OutputPath -TemplatePath $Template -ProfilePath $ProfilePath -Open:$Open -KeepIntermediates:$KeepIntermediates -RetentionRuns $RetentionRuns -PrivacyProfile $PrivacyProfile -AllowMixedSources:$AllowMixedSources -AllowLegacySchema:$AllowLegacySchema
            exit
        }
        default {
            # "A" o cualquier cosa — ejecutar todos
            $RunLic = $true; $RunAdopt = $true; $RunScore = $true
        }
    }
} else {
    # -All sin menu interactivo
    Write-Banner
    Write-ImportantNotice
    $RunLic   = $true
    $RunAdopt = $true
    $RunScore = $true
}

Write-Step "Iniciando recoleccion de datos..." "Cyan"
Write-Host ""
$GlobalStart = Get-Date
$Results = @{ Lic=$null; Adopt=$null; Score=$null; Report=$null }

# ============================================================================
# SESION DE MICROSOFT GRAPH
# ============================================================================
$NeedGraph = $RunLic -or $RunAdopt -or $RunScore
$AllScopes = @("LicenseAssignment.Read.All", "User.Read.All")
if ($NeedGraph) { Write-Step "La sesion Graph sera creada por Licensing y preservada para los collectors siguientes." "Cyan" }

# ============================================================================
# MODULO 1: LICENCIAMIENTO
# ============================================================================
if ($RunLic) {
    Write-Step "[1/3] Ejecutando Get-M365LicensingData.ps1..." "Yellow"
    $T = Get-Date
    try {
        $LicParams = @{
            OutputPath = $OutputPath
            RunId = $RunId
            PreserveGraphSession = $true
        }
        if ($TenantId) { $LicParams.TenantId = $TenantId }
        & $ScriptLic @LicParams
        # Verificar que el licensing REALMENTE produjo datos (el script puede fallar sin
        # lanzar excepcion — p.ej. cuenta MSA sin tenant, o sin permisos — y aun asi retornar).
        $RunLicJson = Join-Path $OutputPath "${RunId}_report_data.json"
        if (Test-Path $RunLicJson) {
            $Results.Lic = "OK ($(Elapsed $T))"
            Write-Step "  [OK] Licenciamiento completado en $(Elapsed $T)" "Green"
            $ExistLic = Get-Item $RunLicJson -ErrorAction SilentlyContinue
        } else {
            $Results.Lic = "ERROR: no se genero report_data.json"
            Write-Step "  [ERROR] Licenciamiento no produjo datos. Verifica una cuenta work/school y el consentimiento de lectura requerido." "Red"
            Write-Step "  [CRIT] No se reutilizan datos de otra corrida — abortando." "Red"
            exit 1
        }
    } catch {
        $Results.Lic = "ERROR: $_"
        Write-Step "  [WARN] Error en Licenciamiento: $_" "Red"
        Write-Step "  [CRIT] No se reutilizan datos de otra corrida — abortando." "Red"
        exit 1
    }
} else {
    Write-Step "[1/3] Licenciamiento: omitido (usando $($ExistLic.Name))" "DarkGray"
    $Results.Lic = "SKIP"
}
Write-Host ""

# ============================================================================
# MODULO 2 & 3: SECURE SCORE + ADOPTION (secuencial)
# ============================================================================

# Elevar la sesion solo con permisos de workloads licenciados.
$EffectiveTenantId = $TenantId
if ($NeedGraph -and $ExistLic) {
    try {
        $LicScopeData = Get-Content $ExistLic.FullName -Raw | ConvertFrom-Json
        if (-not $EffectiveTenantId -and $LicScopeData.TenantId) { $EffectiveTenantId = [string]$LicScopeData.TenantId }
        $DetectedCategories = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($Sku in @($LicScopeData.SKUs)) {
            foreach ($Category in @([string]$Sku.IncludedCategories -split '\s*\|\s*')) {
                if ($Category) { [void]$DetectedCategories.Add($Category) }
            }
        }
        $PostureScopes = [System.Collections.Generic.List[string]]::new()
        $PostureScopes.Add("SecurityEvents.Read.All")
        $PostureScopes.Add("Policy.Read.All")
        $PostureScopes.Add("RoleManagement.Read.Directory")
        $HasP1 = $DetectedCategories.Contains('Entra_ID_P1') -or $DetectedCategories.Contains('Entra_ID_P2')
        $HasP2 = $DetectedCategories.Contains('Entra_ID_P2')
        if ($HasP1) {
            $PostureScopes.Add("AuditLog.Read.All")
        }
        if ($HasP2) {
            $PostureScopes.Add("IdentityRiskyUser.Read.All")
            $PostureScopes.Add("RoleAssignmentSchedule.Read.Directory")
        }
        if ($DetectedCategories.Contains('Entra_ID_Governance')) { $PostureScopes.Add("AccessReview.Read.All") }
        if ($DetectedCategories.Contains('Intune_P1') -or $DetectedCategories.Contains('Intune_P2')) { $PostureScopes.Add("DeviceManagementManagedDevices.Read.All") }
        if (@($DetectedCategories | Where-Object { $_ -match '^(MDE_|MDO_|MDA$|MDI$)' }).Count -gt 0) { $PostureScopes.Add("ThreatHunting.Read.All") }
        if ($DetectedCategories.Contains('Copilot_M365')) { $PostureScopes.Add("Reports.Read.All") }
        $PostureScopes = @($PostureScopes | Sort-Object -Unique)

        $CurrentScopes = @((Get-MgContext).Scopes)
        $MissingPostureScopes = @($PostureScopes | Where-Object { $CurrentScopes -notcontains $_ })
        if ($MissingPostureScopes.Count -gt 0) {
            Write-Step "Solicitando permisos de postura aplicables: $($MissingPostureScopes -join ', ')" "Cyan"
            $ConnectParams = @{ Scopes = @($AllScopes + $PostureScopes | Sort-Object -Unique); NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop' }
            if ($EffectiveTenantId) { $ConnectParams.TenantId = $EffectiveTenantId }
            Connect-MgGraph @ConnectParams
        }
    } catch {
        Write-Step "  [ERROR] No se pudo preparar la sesion de postura: $_" "Red"
        exit 1
    }
}

if ($RunScore) {
    Write-Step "[2/3] Ejecutando Get-M365SecureScore.ps1..." "Yellow"
    $T = Get-Date
    $ExistScore = $null
    try {
        $ScoreParams = @{
            OutputPath = $OutputPath
            RunId = $RunId
            PreserveGraphSession = $true
        }
        if ($EffectiveTenantId) { $ScoreParams.TenantId = $EffectiveTenantId }
        & $ScriptScore @ScoreParams
        $ExistScore = Get-Item (Join-Path $OutputPath "${RunId}_secure_score.json") -ErrorAction SilentlyContinue
        if (-not $ExistScore) { throw "Secure Score no genero el artefacto de la corrida $RunId." }
        $Results.Score = "OK ($(Elapsed $T))"
        Write-Step "  [OK] SecureScore completado en $(Elapsed $T)" "Green"
    } catch {
        $ExistScore = $null
        $Results.Score = "ERROR: $_"
        Write-Step "  [WARN] Error en SecureScore: $_" "Red"
    }
} else {
    Write-Step "[2/3] SecureScore: omitido (usando $($ExistScore.Name))" "DarkGray"
    $Results.Score = "SKIP"
}
Write-Host ""

if ($RunAdopt) {
    Write-Step "[3/3] Ejecutando Get-M365SecurityAdoption.ps1..." "Yellow"
    $T = Get-Date
    try {
        $AdoptParams = @{
            OutputPath = $OutputPath
            DeviceStaleDays = $DeviceStaleDays
            HuntingLookbackDays = [Math]::Max(1, $HuntingLookbackDays)
            RunId = $RunId
            PreserveGraphSession = $true
        }
        if ($ExistLic)   { $AdoptParams.LicensingJsonPath = $ExistLic.FullName }
        if ($ExistScore) { $AdoptParams.SecureScoreJsonPath = $ExistScore.FullName }
        & $ScriptAdopt @AdoptParams
        $ExistAdopt = Get-Item (Join-Path $OutputPath "${RunId}_security_adoption.json") -ErrorAction SilentlyContinue
        if (-not $ExistAdopt) { throw "Adoption no genero el artefacto de la corrida $RunId." }
        $Results.Adopt = "OK ($(Elapsed $T))"
        Write-Step "  [OK] Adoption completado en $(Elapsed $T)" "Green"
    } catch {
        $Results.Adopt = "ERROR: $_"
        Write-Step "  [WARN] Error en Adoption: $_" "Red"
    }
} else {
    Write-Step "[3/3] Adoption: omitido (usando $($ExistAdopt.Name))" "DarkGray"
    $Results.Adopt = "SKIP"
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
        -ProfilePath $ProfilePath `
        -RunId $RunId `
        -LicensingJson $(if ($ExistLic) { $ExistLic.FullName } else { $null }) `
        -AdoptionJson $(if ($ExistAdopt -and $ExistAdopt.Name -like "$RunId*") { $ExistAdopt.FullName } else { $null }) `
        -SecureScoreJson $(if ($ExistScore -and $ExistScore.Name -like "$RunId*") { $ExistScore.FullName } else { $null }) `
        -PrivacyProfile $PrivacyProfile `
        -AllowMixedSources:$AllowMixedSources `
        -AllowLegacySchema:$AllowLegacySchema `
        -RetentionRuns $RetentionRuns `
        -Open:$Open `
        -KeepIntermediates:$KeepIntermediates

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
