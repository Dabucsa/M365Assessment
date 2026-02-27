# Modulos requeridos: Microsoft.Graph.Authentication
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Secure Score Assessment v1
.DESCRIPTION
    Obtiene el Secure Score del tenant, desglosado por categoria,
    y las top recomendaciones de seguridad ordenadas por impacto.
    Ultra liviano: 2-3 requests a Graph API.
.PARAMETER OutputPath
    Carpeta de salida (default: .\output)
.PARAMETER TopRecommendations
    Cantidad de recomendaciones a incluir (default: 20)
.EXAMPLE
    .\Get-MSSecureScore.ps1
    .\Get-MSSecureScore.ps1 -TopRecommendations 30
.NOTES
    Requiere: Global Reader (minimo)
    Modulos:  Microsoft.Graph.Authentication
    Permisos: SecurityEvents.Read.All
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
#>

[CmdletBinding()]
param(
    [string]$OutputPath        = ".\output",
    [int]$TopRecommendations   = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# HELPERS
# ============================================================================
function Write-Section {
    param([string]$Title)
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  [*] $Message" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Red
}

function Invoke-GraphSafe {
    param(
        [string]$Uri,
        [int]$MaxRetries = 3
    )
    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop -OutputType Hashtable
        } catch {
            $ErrMsg = $_.Exception.Message
            if ($ErrMsg -match "403|Forbidden|Authorization|Insufficient") {
                Write-Warn "Sin permisos para: $Uri"
                return $null
            }
            if ($ErrMsg -match "404|NotFound") {
                Write-Warn "No disponible: $Uri"
                return $null
            }
            if ($retry -lt $MaxRetries) {
                # Intentar leer Retry-After del mensaje de error (API lo incluye a veces)
                $Wait = if ($ErrMsg -match '429|Throttl') {
                    $ra = 30
                    if ($ErrMsg -match 'Retry-After[":\s]+([0-9]+)') { $ra = [int]$Matches[1] }
                    elseif ($ErrMsg -match 'retry in ([0-9]+)') { $ra = [int]$Matches[1] }
                    [math]::Min([math]::Max($ra, 10), 120)  # entre 10s y 120s
                } else { 5 }
                Write-Step "Reintentando ($retry/$MaxRetries) en ${Wait}s..."
                Start-Sleep -Seconds $Wait
            } else {
                Write-Warn "Fallo despues de $MaxRetries intentos: $ErrMsg"
                return $null
            }
        }
    }
}

# ============================================================================
# INICIO
# ============================================================================
$ScriptStart = Get-Date

Write-Host ""
Write-Host "  Microsoft 365 Secure Score Assessment" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# ============================================================================
# FASE 1: CONEXION
# ============================================================================
Write-Section "Fase 1: Conexion"

$Scopes = @("SecurityEvents.Read.All")

Write-Step "Conectando a Microsoft Graph..."
$PreExistingSession = $false
try {
    # Intentar reusar sesion existente
    $Context = $null
    try { $Context = Get-MgContext -ErrorAction SilentlyContinue } catch { }

    if ($Context -and $Context.Account) {
        $PreExistingSession = $true
        Write-OK "Reusando sesion existente: $($Context.Account)"
    } else {
        $ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true }
        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext
        Write-OK "Conectado como: $($Context.Account)"
    }
    Write-OK "Tenant: $($Context.TenantId)"
} catch {
    Write-Warn "No se pudo conectar: $_"
    exit 1
}

# ============================================================================
# FASE 2: SECURE SCORE
# ============================================================================
Write-Section "Fase 2: Secure Score"

Write-Step "Obteniendo Secure Score actual..."
$ScoreData = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"

if (-not $ScoreData -or -not $ScoreData.ContainsKey('value') -or $ScoreData.value.Count -eq 0) {
    Write-Warn "No se pudo obtener Secure Score. Verifica permisos (SecurityEvents.Read.All)"
    if (-not $PreExistingSession) { Disconnect-MgGraph | Out-Null }
    exit 1
}

$Score = $ScoreData.value[0]
$CurrentScore  = [math]::Round([double]$Score.currentScore, 1)
$MaxScore      = [math]::Round([double]$Score.maxScore, 1)
$ScorePct      = if ($MaxScore -gt 0) { [math]::Round(($CurrentScore / $MaxScore) * 100, 1) } else { 0 }

Write-Host ""
$ScoreColor = if ($ScorePct -ge 70) { "Green" } elseif ($ScorePct -ge 40) { "Yellow" } else { "Red" }
Write-Host "    ========================================" -ForegroundColor $ScoreColor
Write-Host "      SECURE SCORE:  $CurrentScore / $MaxScore  ($ScorePct%)" -ForegroundColor $ScoreColor
Write-Host "    ========================================" -ForegroundColor $ScoreColor

# Score por categoria
Write-Step "Desglosando por categoria..."
$CategoryScores = @{}
if ($Score.ContainsKey('controlScores') -and $Score.controlScores) {
    foreach ($Control in $Score.controlScores) {
        $Cat = $Control.controlCategory
        if (-not $CategoryScores.ContainsKey($Cat)) {
            $CategoryScores[$Cat] = @{ Current = 0.0; Controls = 0 }
        }
        $CategoryScores[$Cat].Current += [double]$Control.score
        $CategoryScores[$Cat].Controls++
    }
}

# El controlScores no tiene maxScore por control, usamos los controlProfiles para eso
# Por ahora mostramos lo que tenemos

$CategoriesList = [System.Collections.Generic.List[object]]::new()
foreach ($Cat in ($CategoryScores.Keys | Sort-Object)) {
    $CatData = $CategoryScores[$Cat]
    $CatObj = @{
        Category = $Cat
        Score    = [math]::Round($CatData.Current, 1)
        Controls = $CatData.Controls
    }
    $CategoriesList.Add($CatObj)
    Write-Host "    $Cat : $($CatObj.Score) pts ($($CatObj.Controls) controles)" -ForegroundColor White
}

# ============================================================================
# FASE 3: RECOMENDACIONES (CONTROL PROFILES)
# ============================================================================
Write-Section "Fase 3: Recomendaciones de Seguridad"

Write-Step "Obteniendo recomendaciones..."
$AllControlProfiles = [System.Collections.Generic.List[object]]::new()
$NextLink = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=999"
while ($NextLink) {
    $ControlsData = Invoke-GraphSafe -Uri $NextLink
    if ($ControlsData -and $ControlsData.ContainsKey('value')) {
        foreach ($V in $ControlsData.value) { $AllControlProfiles.Add($V) }
    }
    $NextLink = if ($ControlsData -and $ControlsData.ContainsKey('@odata.nextLink')) { $ControlsData.'@odata.nextLink' } else { $null }
}
Write-OK "Control profiles obtenidos: $($AllControlProfiles.Count)"

$Recommendations = [System.Collections.Generic.List[object]]::new()
$TotalMaxScore = 0.0
$CategoryMaxScores = @{}

# Build a set of control IDs that actually exist in this tenant's controlScores
$TenantControlIds = @{}
if ($Score.ContainsKey('controlScores') -and $Score.controlScores) {
    foreach ($CS in $Score.controlScores) {
        $TenantControlIds[$CS.controlName] = $true
    }
}
Write-Step "Controles activos en el tenant: $($TenantControlIds.Count)"

if ($AllControlProfiles.Count -gt 0) {
    foreach ($Ctrl in $AllControlProfiles) {
        # Cap absurd maxScore values (some MS API controls report per-user scaled values like 1000025).
        # A single control cannot logically be worth more than the tenant's declared maxScore.
        $MaxCtrlScoreRaw = [double]$Ctrl.maxScore
        $MaxCtrlScore = if ($MaxScore -gt 0 -and $MaxCtrlScoreRaw -gt $MaxScore) { $MaxScore } else { $MaxCtrlScoreRaw }

        # Only count MaxScore for controls that actually exist in this tenant
        $CtrlCat = $Ctrl.controlCategory
        $IsInTenant = $TenantControlIds.ContainsKey($Ctrl.id)
        if ($IsInTenant) {
            $TotalMaxScore += $MaxCtrlScore
            if (-not $CategoryMaxScores.ContainsKey($CtrlCat)) { $CategoryMaxScores[$CtrlCat] = 0.0 }
            $CategoryMaxScores[$CtrlCat] += $MaxCtrlScore
        }

        # Buscar el score actual de este control
        $CtrlCurrentScore = 0.0
        if ($Score.ContainsKey('controlScores') -and $Score.controlScores) {
            $Match = $Score.controlScores | Where-Object { $_.controlName -eq $Ctrl.id }
            if ($Match) { $CtrlCurrentScore = [double]$Match.score }
        }

        $Improvement = $MaxCtrlScore - $CtrlCurrentScore
        $IsImplemented = $CtrlCurrentScore -ge $MaxCtrlScore

        $RecObj = @{
            Id               = $Ctrl.id
            Title            = $Ctrl.title
            Category         = $CtrlCat
            MaxScore         = $MaxCtrlScore
            CurrentScore     = [math]::Round($CtrlCurrentScore, 1)
            Improvement      = [math]::Round($Improvement, 1)
            IsImplemented    = $IsImplemented
            ImplementationStatus = if ($IsImplemented) { "Implemented" }
                                   elseif ($CtrlCurrentScore -gt 0) { "Partial" }
                                   else { "NotImplemented" }
            Service          = if ($Ctrl.ContainsKey('service')) { $Ctrl.service } else { "" }
            UserImpact       = if ($Ctrl.ContainsKey('userImpact')) { $Ctrl.userImpact } else { "" }
            ImplementationCost = if ($Ctrl.ContainsKey('implementationCost')) { $Ctrl.implementationCost } else { "" }
            Threats          = if ($Ctrl.ContainsKey('threats') -and $Ctrl.threats) { @($Ctrl.threats) } else { @() }
            Tier             = if ($Ctrl.ContainsKey('tier')) { $Ctrl.tier } else { "" }
            Deprecated       = if ($Ctrl.ContainsKey('deprecated') -and $Ctrl.deprecated) { $true } else { $false }
            InTenant         = $IsInTenant
        }
        # Only add controls that are relevant to this tenant
        if ($IsInTenant) {
            $Recommendations.Add($RecObj)
        }
    }
}

# Actualizar categorias con max scores reales
foreach ($Cat in $CategoriesList) {
    $CatName = $Cat.Category
    if ($CategoryMaxScores.ContainsKey($CatName)) {
        $Cat.MaxScore = [math]::Round($CategoryMaxScores[$CatName], 1)
        $Cat.PctScore = if ($Cat.MaxScore -gt 0) { [math]::Round(($Cat.Score / $Cat.MaxScore) * 100, 1) } else { 0 }
    }
}

# Filtrar recomendaciones no implementadas, no deprecadas, ordenar por impacto
$ActionableRecs = @($Recommendations |
    Where-Object { -not $_.IsImplemented -and -not $_.Deprecated -and $_.Improvement -gt 0 } |
    Sort-Object { $_.Improvement } -Descending |
    Select-Object -First $TopRecommendations)

$ImplementedCount    = @($Recommendations | Where-Object { $_.IsImplemented }).Count
$PartialCount        = @($Recommendations | Where-Object { $_.ImplementationStatus -eq "Partial" }).Count
$NotImplementedCount = @($Recommendations | Where-Object { $_.ImplementationStatus -eq "NotImplemented" -and -not $_.Deprecated }).Count
$DeprecatedCount     = @($Recommendations | Where-Object { $_.Deprecated }).Count

Write-OK "Total controles: $($Recommendations.Count)"
Write-Host "    Implementados:       $ImplementedCount" -ForegroundColor Green
Write-Host "    Parciales:           $PartialCount" -ForegroundColor Yellow
Write-Host "    No implementados:    $NotImplementedCount" -ForegroundColor Red
Write-Host "    Deprecados:          $DeprecatedCount" -ForegroundColor DarkGray

# Categorias actualizadas
Write-Host ""
Write-Step "Score por categoria:"
foreach ($Cat in $CategoriesList) {
    $CatColor = if ($Cat.ContainsKey('PctScore')) {
        if ($Cat.PctScore -ge 70) { "Green" } elseif ($Cat.PctScore -ge 40) { "Yellow" } else { "Red" }
    } else { "White" }
    $PctText = if ($Cat.ContainsKey('PctScore')) { " ($($Cat.PctScore)%)" } else { "" }
    $MaxText = if ($Cat.ContainsKey('MaxScore')) { "/$($Cat.MaxScore)" } else { "" }
    Write-Host ("    {0,-25} {1,5}{2}  {3}" -f $Cat.Category, $Cat.Score, $MaxText, $PctText) -ForegroundColor $CatColor
}

# Top recomendaciones
Write-Host ""
Write-Step "Top $TopRecommendations recomendaciones por impacto:"
$i = 0
foreach ($Rec in $ActionableRecs) {
    $i++
    $RecColor = if ($Rec.Improvement -ge 5) { "Red" } elseif ($Rec.Improvement -ge 2) { "Yellow" } else { "White" }
    $StatusIcon = if ($Rec.ImplementationStatus -eq "Partial") { "[~]" } else { "[ ]" }
    Write-Host ("    {0,2}. {1} +{2} pts  {3}" -f $i, $StatusIcon, $Rec.Improvement, $Rec.Title) -ForegroundColor $RecColor
    Write-Host ("                       Categoria: {0} | Servicio: {1}" -f $Rec.Category, $Rec.Service) -ForegroundColor DarkGray
}

# ============================================================================
# FASE 4: EXPORTAR JSON
# ============================================================================
Write-Section "Fase 4: Exportando resultados"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$Result = @{
    GeneratedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion   = "1.0"
    TenantId        = $Context.TenantId
    Score           = @{
        Current     = $CurrentScore
        Max         = $MaxScore
        Pct         = $ScorePct
    }
    Categories      = @($CategoriesList)
    Summary         = @{
        TotalControls    = $Recommendations.Count
        Implemented      = $ImplementedCount
        Partial          = $PartialCount
        NotImplemented   = $NotImplementedCount
        Deprecated       = $DeprecatedCount
    }
    TopRecommendations = @($ActionableRecs)
    AllRecommendations = @($Recommendations | Where-Object { -not $_.Deprecated })
}

$JsonPath = Join-Path $OutputPath "${Timestamp}_secure_score.json"
$Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-OK "JSON: $JsonPath"

# ============================================================================
# RESUMEN FINAL
# ============================================================================
$Duration = (Get-Date) - $ScriptStart

Write-Section "COMPLETADO en $([math]::Round($Duration.TotalSeconds)) segundos"
Write-Host ""
Write-Host "    SECURE SCORE:  $CurrentScore / $MaxScore  ($ScorePct%)" -ForegroundColor $ScoreColor
Write-Host ""
Write-Host "    Implementados:      $ImplementedCount controles" -ForegroundColor Green
Write-Host "    Por mejorar:        $($PartialCount + $NotImplementedCount) controles" -ForegroundColor Yellow
Write-Host "    Impacto potencial:  +$(($ActionableRecs | ForEach-Object { $_.Improvement } | Measure-Object -Sum).Sum) pts si se implementa el top $TopRecommendations" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Resultados en: $JsonPath" -ForegroundColor Cyan

Write-Host ""
if (-not $PreExistingSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion cerrada`n"
} else {
    Write-OK "Sesion mantenida (orquestador)`n"
}
