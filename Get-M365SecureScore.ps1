# Modulos requeridos: Microsoft.Graph.Authentication
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Secure Score Assessment v4
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
    Requiere consentimiento para SecurityEvents.Read.All.
    Modulos:  Microsoft.Graph.Authentication
    Permisos: SecurityEvents.Read.All
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath        = ".\output",
    [ValidateRange(1, 100)]
    [int]$TopRecommendations   = 20,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,
    [switch]$PreserveGraphSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$OnWindowsHost = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }
$script:GraphFailures = [System.Collections.Generic.List[string]]::new()
$script:ReconnectAttempted = $false

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

function Get-TenantFingerprint {
    param([Parameter(Mandatory = $true)][string]$Value)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
        return ([System.BitConverter]::ToString($Sha.ComputeHash($Bytes)).Replace('-', '').Substring(0, 16).ToLowerInvariant())
    } finally { $Sha.Dispose() }
}

function Get-ContextTenantId {
    param($Context)
    if (-not $Context) { return $null }
    if ($Context.PSObject.Properties['TenantId'] -and $Context.TenantId) { return [string]$Context.TenantId }
    return $null
}

function Get-ContextScopes {
    param($Context)
    if (-not $Context) { return @() }
    if ($Context.PSObject.Properties['Scopes'] -and $Context.Scopes) { return @($Context.Scopes | ForEach-Object { [string]$_ }) }
    return @()
}

function Test-GraphContextRequirements {
    param(
        $Context,
        [string[]]$RequiredScopes,
        [string]$RequiredTenantId
    )

    if (-not $Context -or -not $Context.Account) { return $false }

    $ContextTenantId = Get-ContextTenantId -Context $Context
    if ($RequiredTenantId -match '^[0-9a-fA-F-]{36}$' -and (-not $ContextTenantId -or $ContextTenantId -ne $RequiredTenantId)) { return $false }

    $ContextScopes = Get-ContextScopes -Context $Context
    foreach ($Scope in $RequiredScopes) {
        if ($ContextScopes -notcontains $Scope) { return $false }
    }

    return $true
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
            if ($ErrMsg -match 'Authentication needed|not authenticated|call Connect-MgGraph' -and -not $script:ReconnectAttempted) {
                $script:ReconnectAttempted = $true
                Write-Step "Sesion Graph no utilizable; reconectando una vez..."
                try {
                    $ReconnectParams = @{ Scopes = @('SecurityEvents.Read.All'); NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop' }
                    if ($TenantId) { $ReconnectParams.TenantId = $TenantId }
                    Connect-MgGraph @ReconnectParams
                    $script:ManagedSession = $true
                    continue
                } catch {
                    $script:GraphFailures.Add($Uri)
                    Write-Warn "No se pudo restablecer la sesion Graph: $($_.Exception.Message)"
                    return $null
                }
            }
            if ($ErrMsg -match "403|Forbidden|Authorization|Insufficient") {
                $script:GraphFailures.Add($Uri)
                Write-Warn "Sin permisos para: $Uri"
                return $null
            }
            if ($ErrMsg -match "404|NotFound") {
                $script:GraphFailures.Add($Uri)
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
                $script:GraphFailures.Add($Uri)
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
if (-not $OnWindowsHost) { & /bin/chmod 700 $OutputPath }

# ============================================================================
# FASE 1: CONEXION
# ============================================================================
Write-Section "Fase 1: Conexion"

$Scopes = @("SecurityEvents.Read.All")

Write-Step "Conectando a Microsoft Graph..."
$ManagedSession = $false
try {
    $ExistingContext = $null
    try { $ExistingContext = Get-MgContext -ErrorAction SilentlyContinue } catch { }

    if (Test-GraphContextRequirements -Context $ExistingContext -RequiredScopes $Scopes -RequiredTenantId $TenantId) {
        $Context = $ExistingContext
        Write-OK "Reusando sesion delegada existente"
    } else {
        if ($ExistingContext -and $ExistingContext.Account) {
            Write-Step "La sesion existente no cumple tenant/scopes requeridos; abriendo sesion dedicada..."
        }
        $ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true; ContextScope = 'Process' }
        if ($TenantId) { $ConnectParams.TenantId = $TenantId }
        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext
        $ManagedSession = $true
        if (-not (Test-GraphContextRequirements -Context $Context -RequiredScopes $Scopes -RequiredTenantId $TenantId)) {
            throw "La sesion Graph no quedo asociada al tenant/scopes requeridos."
        }
        Write-OK "Sesion delegada conectada"
    }
    Write-OK "Contexto Graph validado"
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
    $FailureMessage = "No se pudo obtener Secure Score. Verifica sesion y permiso SecurityEvents.Read.All."
    Write-Warn $FailureMessage
    if ($ManagedSession -and -not $PreserveGraphSession) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }
    throw $FailureMessage
}

$Score = $ScoreData.value[0]
$CurrentScore  = [math]::Round([double]$Score.currentScore, 1)
$MaxScore      = [math]::Round([double]$Score.maxScore, 1)
$ScorePct      = if ($MaxScore -gt 0) { [math]::Round(($CurrentScore / $MaxScore) * 100, 1) } else { $null }

# Comparacion con otros tenants (viene en la MISMA respuesta de secureScores; puede faltar).
# Da contexto al ejecutivo: tu score vs. el promedio de tenants / de tu mismo tamano / industria.
$Comparative = @{}
if ($Score.ContainsKey('averageComparativeScores') -and $Score.averageComparativeScores) {
    foreach ($c in $Score.averageComparativeScores) {
        switch ("$($c.basis)") {
            'AllTenants'    { $Comparative.AllTenants    = [math]::Round([double]$c.averageScore, 1) }
            'TotalSeats'    { $Comparative.TotalSeats    = [math]::Round([double]$c.averageScore, 1) }
            'IndustryTypes' { $Comparative.IndustryTypes = [math]::Round([double]$c.averageScore, 1) }
        }
    }
    if ($Comparative.Count -gt 0) { Write-Host "    Comparativa disponible (AllTenants/TotalSeats/IndustryTypes)" -ForegroundColor DarkGray }
}

Write-Host ""
$ScoreColor = if ($null -eq $ScorePct) { "White" } elseif ($ScorePct -ge 70) { "Green" } elseif ($ScorePct -ge 40) { "Yellow" } else { "Red" }
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
        # No alterar silenciosamente valores de Graph. Si un maxScore de control es
        # mayor que el maximo total del tenant, se marca invalido y no se usa para
        # porcentajes/priorizacion.
        $MaxCtrlScoreRaw = [double]$Ctrl.maxScore
        $ScoreDataQuality = if ($MaxCtrlScoreRaw -lt 0 -or ($MaxScore -gt 0 -and $MaxCtrlScoreRaw -gt $MaxScore)) { "invalid" } else { "valid" }
        $MaxCtrlScore = if ($ScoreDataQuality -eq "valid") { $MaxCtrlScoreRaw } else { $null }

        # Only count MaxScore for controls that actually exist in this tenant
        $CtrlCat = $Ctrl.controlCategory
        $IsInTenant = $TenantControlIds.ContainsKey($Ctrl.id)
        if ($IsInTenant -and $null -ne $MaxCtrlScore) {
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

        $Improvement = if ($null -ne $MaxCtrlScore) { $MaxCtrlScore - $CtrlCurrentScore } else { $null }
        $IsImplemented = if ($null -ne $MaxCtrlScore) { $CtrlCurrentScore -ge $MaxCtrlScore } else { $false }

        $RecObj = @{
            Id               = $Ctrl.id
            Title            = $Ctrl.title
            Category         = $CtrlCat
            MaxScore         = $MaxCtrlScore
            CurrentScore     = [math]::Round($CtrlCurrentScore, 1)
            Improvement      = if ($null -ne $Improvement) { [math]::Round($Improvement, 1) } else { $null }
            IsImplemented    = $IsImplemented
            ImplementationStatus = if ($ScoreDataQuality -ne "valid") { "Unknown" }
                                   elseif ($IsImplemented) { "Implemented" }
                                   elseif ($CtrlCurrentScore -gt 0) { "Partial" }
                                   else { "NotImplemented" }
            DataQuality      = $ScoreDataQuality
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
        $Cat.PctScore = if ($Cat.MaxScore -gt 0) { [math]::Round(($Cat.Score / $Cat.MaxScore) * 100, 1) } else { $null }
    }
}

# Prioridad reproducible basada en la ganancia potencial informada por Secure Score.
# No es una severidad de Microsoft ni reemplaza el contexto de riesgo del cliente.
$OrderedRecommendations = @($Recommendations |
    Where-Object { -not $_.Deprecated } |
    Sort-Object `
        @{ Expression = { if ($_.DataQuality -eq 'valid' -and -not $_.IsImplemented -and $_.Improvement -gt 0) { 0 } else { 1 } }; Ascending = $true }, `
        @{ Expression = { if ($null -ne $_.Improvement) { [double]$_.Improvement } else { -1 } }; Descending = $true }, `
        @{ Expression = { [string]$_.Title }; Ascending = $true })

$PriorityRank = 0
foreach ($Rec in $OrderedRecommendations) {
    $IsActionable = $Rec.DataQuality -eq 'valid' -and -not $Rec.IsImplemented -and $Rec.Improvement -gt 0
    if ($IsActionable) {
        $PriorityRank++
        $Rec['PriorityRank'] = $PriorityRank
        $Rec['PriorityBand'] = if ([double]$Rec.Improvement -ge 5) { 'High' }
                               elseif ([double]$Rec.Improvement -ge 2) { 'Medium' }
                               else { 'Low' }
    }
    else {
        $Rec['PriorityRank'] = $null
        $Rec['PriorityBand'] = if ($Rec.IsImplemented) { 'Complete' } else { 'NotPrioritized' }
    }
}

$ActionableRecs = @($OrderedRecommendations |
    Where-Object { $_.PriorityRank -ne $null } |
    Select-Object -First $TopRecommendations)

$ImplementedCount    = @($Recommendations | Where-Object { $_.IsImplemented }).Count
$PartialCount        = @($Recommendations | Where-Object { $_.ImplementationStatus -eq "Partial" }).Count
$NotImplementedCount = @($Recommendations | Where-Object { $_.ImplementationStatus -eq "NotImplemented" -and -not $_.Deprecated }).Count
$DeprecatedCount     = @($Recommendations | Where-Object { $_.Deprecated }).Count
$InvalidCount        = @($Recommendations | Where-Object { $_.DataQuality -eq 'invalid' }).Count

Write-OK "Total controles: $($Recommendations.Count)"
Write-Host "    Implementados:       $ImplementedCount" -ForegroundColor Green
Write-Host "    Parciales:           $PartialCount" -ForegroundColor Yellow
Write-Host "    No implementados:    $NotImplementedCount" -ForegroundColor Red
Write-Host "    Deprecados:          $DeprecatedCount" -ForegroundColor DarkGray

# Categorias actualizadas
Write-Host ""
Write-Step "Score por categoria:"
foreach ($Cat in $CategoriesList) {
    $CatColor = if ($Cat.ContainsKey('PctScore') -and $null -ne $Cat.PctScore) {
        if ($Cat.PctScore -ge 70) { "Green" } elseif ($Cat.PctScore -ge 40) { "Yellow" } else { "Red" }
    } else { "White" }
    $PctText = if ($Cat.ContainsKey('PctScore') -and $null -ne $Cat.PctScore) { " ($($Cat.PctScore)%)" } else { " (N/D)" }
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
    Write-Host ("    {0,2}. {1} +{2} pts  {3}" -f $Rec.PriorityRank, $StatusIcon, $Rec.Improvement, $Rec.Title) -ForegroundColor $RecColor
    Write-Host ("                       Categoria: {0} | Servicio: {1}" -f $Rec.Category, $Rec.Service) -ForegroundColor DarkGray
}

# ============================================================================
# FASE 4: EXPORTAR JSON
# ============================================================================
Write-Section "Fase 4: Exportando resultados"

$OutputPrefix = if ($RunId) { $RunId } else { Get-Date -Format "yyyyMMdd_HHmm" }
$Result = @{
    RunId           = $OutputPrefix
    GeneratedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion   = "4.1"
    SchemaVersion   = "4.0"
    TenantId        = $Context.TenantId
    TenantFingerprint = Get-TenantFingerprint -Value ([string]$Context.TenantId)
    Collection      = @{
        Status = if ($script:GraphFailures.Count -gt 0 -or $AllControlProfiles.Count -eq 0 -or $InvalidCount -gt 0) { "partial" } else { "success" }
        Source = "Microsoft Graph Secure Score"
        FailedRequests = $script:GraphFailures.Count
        InvalidControls = $InvalidCount
    }
    Score           = @{
        Current     = $CurrentScore
        Max         = $MaxScore
        Pct         = $ScorePct
        Comparative = $Comparative
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
    AllRecommendations = @($OrderedRecommendations)
}

$JsonPath = Join-Path $OutputPath "${OutputPrefix}_secure_score.json"
$Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
if (-not $OnWindowsHost) { & /bin/chmod 600 $JsonPath }
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
if ($ManagedSession -and -not $PreserveGraphSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion dedicada cerrada`n"
} else {
    Write-OK "Sesion Graph mantenida`n"
}
