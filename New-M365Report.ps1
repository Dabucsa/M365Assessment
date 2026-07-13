#Requires -Version 5.1
<#
.SYNOPSIS
    Genera el reporte HTML de M365 Security Assessment a partir de JSON/CSV.
.DESCRIPTION
    Lee los archivos de datos, construye un JSON compacto y lo inyecta en
    report-template.html reemplazando el placeholder __REPORT_DATA__.
    El template es HTML/JS puro, sin expresiones PowerShell.
.PARAMETER OutputPath
    Carpeta donde buscar los JSON/CSV y donde escribir el HTML. Default: .\output
.PARAMETER LicensingJson
    Ruta explicita al _report_data.json (auto-detecta si no se pasa).
.PARAMETER AdoptionJson
    Ruta explicita al _security_adoption.json (opcional).
.PARAMETER SecureScoreJson
    Ruta explicita al _secure_score.json (opcional).
.PARAMETER TemplatePath
    Ruta al template HTML. Default: .\report-template.html junto al script.
.PARAMETER ProfilePath
    Perfil versionado con umbrales, modelo de riesgo y catálogo de controles.
.PARAMETER ReportName
    Nombre personalizado para el HTML de salida.
.PARAMETER Open
    Abrir el reporte en el browser al terminar.
.PARAMETER KeepIntermediates
    Conserva los CSV/JSON intermedios (datos sensibles del tenant). Por defecto se envian a la
    Papelera tras generar el HTML, dejando el reporte depurado como unico artefacto.
.PARAMETER AllowLegacySchema
    Permite migrar explicitamente artefactos v3. Las metricas no verificables se
    convierten a N/D y el reporte queda marcado como legacy.
.EXAMPLE
    .\New-M365Report.ps1 -OutputPath ".\output"
#>
param(
    [string]$OutputPath     = ".\output",
    [string]$LicensingJson,
    [string]$AdoptionJson,
    [string]$SecureScoreJson,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,
    [string]$TemplatePath   = "$PSScriptRoot\report-template.html",
    [string]$ProfilePath    = "$PSScriptRoot/assessment-profile.json",
    [string]$ReportName,
    [ValidateSet("Shareable", "Internal")]
    [string]$PrivacyProfile = "Shareable",
    [switch]$AllowMixedSources,
    [switch]$AllowLegacySchema,
    [switch]$Open,
    [switch]$KeepIntermediates,
    # Reportes HTML historicos a conservar (los mas viejos van a la Papelera).
    # Cada HTML contiene la postura completa del tenant: acumularlos sin limite
    # agranda la superficie de fuga. 0 = conservar todo.
    [ValidateRange(0, 100)]
    [int]$RetentionRuns = 5
)
$ErrorActionPreference = "Stop"
$OnWindowsHost = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }
if ($ReportName -and ($ReportName -in @('.', '..') -or [IO.Path]::GetFileName($ReportName) -ne $ReportName -or $ReportName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0)) {
    throw "ReportName debe ser un nombre de archivo, sin ruta ni caracteres invalidos."
}

function Get-TenantFingerprint {
    param([Parameter(Mandatory = $true)][string]$Value)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())
        return ([System.BitConverter]::ToString($Sha.ComputeHash($Bytes)).Replace('-', '').Substring(0, 16).ToLowerInvariant())
    } finally { $Sha.Dispose() }
}

function Copy-CanonicalProperty {
    param($Object, [string]$Target, [string]$Source)
    if (-not $Object -or $Object.PSObject.Properties[$Target] -or -not $Object.PSObject.Properties[$Source]) { return }
    $Object | Add-Member -NotePropertyName $Target -NotePropertyValue $Object.$Source -Force
}

function Get-FileSha256Lower {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-CatalogControl {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)][string]$Id
    )
    return ($Profile.ControlCatalog | Where-Object { [string]$_.Id -eq $Id } | Select-Object -First 1)
}

function Get-AssessmentPriority {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)][string]$RiskSeverity,
        [Parameter(Mandatory = $true)][string]$Confidence,
        [double]$SecureScoreGain = 0,
        [Parameter(Mandatory = $true)][int]$HorizonDays
    )
    $Model = $Profile.RiskModel
    $SeverityValue = [double]$Model.SeverityScores.$RiskSeverity
    $ConfidenceValue = [double]$Model.ConfidenceScores.$Confidence
    $UrgencyValue = if ($Model.UrgencyScores.PSObject.Properties[[string]$HorizonDays]) {
        [double]$Model.UrgencyScores.PSObject.Properties[[string]$HorizonDays].Value
    } else { 30.0 }
    $GainValue = [math]::Min(100.0, [math]::Max(0.0, $SecureScoreGain * 10.0))
    $Score = [math]::Round(
        ($SeverityValue * [double]$Model.Weights.RiskSeverity) +
        ($ConfidenceValue * [double]$Model.Weights.Confidence) +
        ($GainValue * [double]$Model.Weights.SecureScoreGain) +
        ($UrgencyValue * [double]$Model.Weights.Urgency), 1)
    $Band = if ($RiskSeverity -eq 'Critical' -and $Score -ge [double]$Model.Bands.Critical) { 'Critical' }
            elseif ($RiskSeverity -in @('Critical','High') -and $Score -ge [double]$Model.Bands.HighRiskFloor) { 'High' }
            elseif ($Score -ge [double]$Model.Bands.High) { 'High' }
            elseif ($Score -ge [double]$Model.Bands.Medium) { 'Medium' }
            else { 'Low' }
    return [PSCustomObject]@{ Score = $Score; Band = $Band }
}

function New-AssessmentFinding {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)]$Control,
        [Parameter(Mandatory = $true)][string]$ControlId,
        [string]$Title,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [double]$SecureScoreGain = 0,
        [string]$Source = 'Posture',
        [string]$RiskSeverity,
        [string]$Confidence,
        [int]$HorizonDays = 0
    )
    $EffectiveSeverity = if ($RiskSeverity) { $RiskSeverity } else { [string]$Control.RiskSeverity }
    $EffectiveConfidence = if ($Confidence) { $Confidence } else { [string]$Control.Confidence }
    $EffectiveHorizon = if ($HorizonDays -gt 0) { $HorizonDays } else { [int]$Control.HorizonDays }
    $Priority = Get-AssessmentPriority -Profile $Profile -RiskSeverity $EffectiveSeverity -Confidence $EffectiveConfidence -SecureScoreGain $SecureScoreGain -HorizonDays $EffectiveHorizon
    return [PSCustomObject][ordered]@{
        ControlId          = $ControlId
        Title              = if ($Title) { $Title } else { [string]$Control.Title }
        Source             = $Source
        RiskSeverity       = $EffectiveSeverity
        Confidence         = $EffectiveConfidence
        PriorityScore      = $Priority.Score
        PriorityBand       = $Priority.Band
        HorizonDays        = $EffectiveHorizon
        Owner              = [string]$Control.Owner
        Evidence           = $Evidence
        EvidenceSource     = [string]$Control.EvidenceSource
        ValidationCriterion = [string]$Control.ValidationCriterion
        SecureScoreGain    = if ($SecureScoreGain -gt 0) { [math]::Round($SecureScoreGain, 1) } else { $null }
        NistCsf20          = [string]$Control.NistCsf20
        ZeroTrustPillar    = [string]$Control.ZeroTrustPillar
        Status             = 'Open'
    }
}

function Get-ModuleStatusValue {
    param($AdoptionData, [Parameter(Mandatory = $true)][string]$Name)
    if (-not $AdoptionData -or -not $AdoptionData.ModuleStatus) { return $null }
    $Property = $AdoptionData.ModuleStatus.PSObject.Properties[$Name]
    if ($Property) { return $Property.Value }
    return $null
}

function Get-OptionalPropertyValue {
    param($Object, [Parameter(Mandatory = $true)][string]$Name)
    if (-not $Object) { return $null }
    $Property = $Object.PSObject.Properties[$Name]
    if ($Property) { return $Property.Value }
    return $null
}

# ── Enviar archivos a la Papelera (recuperable, multiplataforma) ────────────
# Se usa al final para que el UNICO artefacto persistente sea el HTML depurado.
# Papelera (no borrado permanente) = red de seguridad si algo falla.
function Move-ToTrash {
    param([Parameter(Mandatory)][string[]]$Path)
    foreach ($p in $Path) {
        if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path -LiteralPath $p)) { continue }
        $full = (Resolve-Path -LiteralPath $p).Path
        $name = Split-Path $full -Leaf
        try {
            if ($OnWindowsHost) {
                Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
                    $full,
                    [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
                    [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
            } elseif ($IsMacOS) {
                $trashDir = Join-Path $HOME '.Trash'
                $destination = Join-Path $trashDir $name
                if (Test-Path -LiteralPath $destination) {
                    $destination = Join-Path $trashDir ("{0}_{1}{2}" -f [IO.Path]::GetFileNameWithoutExtension($name), [guid]::NewGuid().ToString('N').Substring(0,8), [IO.Path]::GetExtension($name))
                }
                Move-Item -LiteralPath $full -Destination $destination
            } else {
                if (Get-Command gio -ErrorAction SilentlyContinue) {
                    & gio trash -- "$full" 2>$null
                } else {
                    $trashDir = Join-Path $HOME '.local/share/Trash/files'
                    New-Item -ItemType Directory -Force -Path $trashDir | Out-Null
                    Move-Item -LiteralPath $full -Destination $trashDir -Force
                }
            }
            Write-Host "  [Papelera] $name" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [WARN] No se pudo enviar a Papelera '$name': $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "         Eliminalo manualmente: $full" -ForegroundColor Yellow
        }
    }
}

# ── Restringir permisos del artefacto (cross-platform) ──────────────────────
# El HTML/manifest contienen la postura completa del tenant y no deben quedar
# legibles para otros usuarios locales. Unix: chmod. Windows: icacls con SIDs
# (SYSTEM y Administradores por SID para ser independiente del idioma del SO).
function Protect-Path {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        if ($OnWindowsHost) {
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls $Path /inheritance:r /grant:r "${me}:(F)" "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" *> $null
        } else {
            & /bin/chmod ($(if ($Directory) { '700' } else { '600' })) $Path
        }
    } catch {
        Write-Host "  [WARN] No se pudieron restringir permisos de '$Path': $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ── Carpeta de salida ──────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path
Protect-Path -Path $OutputPath -Directory

# ── Auto-detectar archivos ─────────────────────────────────────────────────
function Find-Latest([string]$Dir,[string]$Filter){
    Get-ChildItem $Dir -Filter $Filter -EA SilentlyContinue |
        Sort-Object LastWriteTime -Desc | Select-Object -First 1
}
if (-not $LicensingJson) {
    $f = if ($RunId) { Get-Item (Join-Path $OutputPath "${RunId}_report_data.json") -ErrorAction SilentlyContinue } else { Find-Latest $OutputPath "*_report_data.json" }
    if ($f) { $LicensingJson = $f.FullName }
}

if (-not $LicensingJson -or -not (Test-Path $LicensingJson)) {
    Write-Error "No se encontró _report_data.json. Ejecuta Get-M365LicensingData.ps1 primero."
}
if (-not (Test-Path $TemplatePath)) { Write-Error "Template no encontrado: $TemplatePath" }
if (-not (Test-Path $ProfilePath)) { Write-Error "Perfil de assessment no encontrado: $ProfilePath" }

Write-Host "[M365 Report] Renderer v4.2" -ForegroundColor Cyan
Write-Host "  Licensing:   $LicensingJson"   -ForegroundColor Yellow
if ($AdoptionJson)    { Write-Host "  Adoption:    $AdoptionJson"    -ForegroundColor Yellow }
if ($SecureScoreJson) { Write-Host "  SecureScore: $SecureScoreJson" -ForegroundColor Yellow }
Write-Host "  Profile:     $ProfilePath" -ForegroundColor Yellow

# ── Cargar datos ──────────────────────────────────────────────────────────
$LicData   = Get-Content $LicensingJson -Raw -Encoding UTF8 | ConvertFrom-Json
$AssessmentProfile = Get-Content $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $AssessmentProfile.SchemaVersion -or [string]$AssessmentProfile.SchemaVersion -ne '1.0') {
    throw "Perfil de assessment inválido: SchemaVersion 1.0 requerido."
}
if (-not $AssessmentProfile.RiskModel -or -not $AssessmentProfile.ControlCatalog) {
    throw "Perfil de assessment inválido: RiskModel y ControlCatalog son obligatorios."
}
$ProfileControlIds = @($AssessmentProfile.ControlCatalog | ForEach-Object { [string]$_.Id })
if ($ProfileControlIds.Count -ne @($ProfileControlIds | Sort-Object -Unique).Count) {
    throw "Perfil de assessment inválido: ControlCatalog contiene IDs duplicados."
}
$RequiredControlIds = @('EVID-MFA','ENTRA-MFA-CAPABLE','ENTRA-CA-LEGACY','ENTRA-CA-PRIV-MFA','ENTRA-CA-EXCLUSIONS','ENTRA-BASELINE','ENTRA-RISK-HIGH','ENTRA-GA-COUNT','ENTRA-PIM-PERM','MDI-SENSORS','INTUNE-ENROLLMENT','EVID-MODULE','MS-SECURESCORE')
$MissingControlIds = @($RequiredControlIds | Where-Object { $ProfileControlIds -notcontains $_ })
if ($MissingControlIds.Count -gt 0) {
    throw "Perfil de assessment inválido: faltan controles obligatorios: $($MissingControlIds -join ', ')."
}
$RiskWeights = $AssessmentProfile.RiskModel.Weights
$WeightTotal = [double]$RiskWeights.RiskSeverity + [double]$RiskWeights.Confidence + [double]$RiskWeights.SecureScoreGain + [double]$RiskWeights.Urgency
if ([math]::Abs($WeightTotal - 1.0) -gt 0.0001) {
    throw "Perfil de assessment inválido: los pesos de RiskModel deben sumar 1.0."
}
foreach ($Control in $AssessmentProfile.ControlCatalog) {
    if ([string]::IsNullOrWhiteSpace([string]$Control.Id) -or [string]::IsNullOrWhiteSpace([string]$Control.Title) -or
        [string]::IsNullOrWhiteSpace([string]$Control.Owner) -or [string]::IsNullOrWhiteSpace([string]$Control.ValidationCriterion)) {
        throw "Perfil de assessment inválido: cada control requiere Id, Title, Owner y ValidationCriterion."
    }
    if ([string]$Control.RiskSeverity -notin @('Critical','High','Medium','Low') -or [string]$Control.Confidence -notin @('High','Medium','Low') -or [int]$Control.HorizonDays -notin @(30,60,90)) {
        throw "Perfil de assessment inválido en '$($Control.Id)': RiskSeverity, Confidence o HorizonDays fuera de catálogo."
    }
}
$EffectiveRunId = if ($RunId) { $RunId } elseif ($LicData.RunId) { [string]$LicData.RunId } else { ([IO.Path]::GetFileName($LicensingJson) -replace '_report_data\.json$', '') }
if (-not $AdoptionJson) {
    $f = Get-Item (Join-Path $OutputPath "${EffectiveRunId}_security_adoption.json") -ErrorAction SilentlyContinue
    if ($f) { $AdoptionJson = $f.FullName }
}
if (-not $SecureScoreJson) {
    $f = Get-Item (Join-Path $OutputPath "${EffectiveRunId}_secure_score.json") -ErrorAction SilentlyContinue
    if ($f) { $SecureScoreJson = $f.FullName }
}
$AdoptData = if ($AdoptionJson    -and (Test-Path $AdoptionJson))    { Get-Content $AdoptionJson    -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
$ScoreData = if ($SecureScoreJson -and (Test-Path $SecureScoreJson)) { Get-Content $SecureScoreJson -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }

# Integridad de corrida/tenant. Las fuentes opcionales pueden faltar, pero nunca
# se mezclan silenciosamente con otra corrida o tenant.
$ValidationErrors = [System.Collections.Generic.List[string]]::new()
$LegacySources = [System.Collections.Generic.List[string]]::new()
foreach ($Pair in @(@{ Name = 'lic'; Data = $LicData }, @{ Name = 'adopt'; Data = $AdoptData }, @{ Name = 'score'; Data = $ScoreData })) {
    if (-not $Pair.Data) { continue }
    $Schema = if ($Pair.Data.PSObject.Properties['SchemaVersion']) { [string]$Pair.Data.SchemaVersion } else { '' }
    if ($Schema -ne '4.0') { $LegacySources.Add($Pair.Name) }
    if ($Pair.Data.PSObject.Properties['RunId'] -and $Pair.Data.RunId) {
        if ([string]$Pair.Data.RunId -ne $EffectiveRunId) { $ValidationErrors.Add("$($Pair.Name): RunId distinto") }
    } elseif ($Schema -eq '4.0') {
        $ValidationErrors.Add("$($Pair.Name): RunId ausente")
    }
    if ($Schema -eq '4.0' -and (-not $Pair.Data.PSObject.Properties['TenantFingerprint'] -or -not $Pair.Data.TenantFingerprint)) {
        $ValidationErrors.Add("$($Pair.Name): TenantFingerprint ausente")
    }
    if ($LicData.PSObject.Properties['TenantFingerprint'] -and $LicData.TenantFingerprint -and
        $Pair.Data.PSObject.Properties['TenantFingerprint'] -and $Pair.Data.TenantFingerprint -and
        [string]$Pair.Data.TenantFingerprint -ne [string]$LicData.TenantFingerprint) {
        $ValidationErrors.Add("$($Pair.Name): tenant distinto")
    } elseif ($LicData.PSObject.Properties['TenantId'] -and $Pair.Data.PSObject.Properties['TenantId'] -and
              $LicData.TenantId -and $Pair.Data.TenantId -and [string]$Pair.Data.TenantId -ne [string]$LicData.TenantId) {
        $ValidationErrors.Add("$($Pair.Name): tenant distinto")
    }
}
if ($LegacySources.Count -gt 0 -and -not $AllowLegacySchema) {
    throw "Esquema legacy rechazado en: $($LegacySources -join ', '). Use -AllowLegacySchema solo para migrar un reporte historico; ejecute una corrida v4 para evidencia final."
}
if ($ValidationErrors.Count -gt 0 -and -not $AllowMixedSources) {
    throw "Integridad de fuentes rechazada: $($ValidationErrors -join '; '). Use -AllowMixedSources solo para investigacion, nunca para un assessment final."
}

# Migracion conservadora v3 -> v4. Solo se trasladan campos cuya semantica se
# mantiene; cobertura CA/MDE, optimizacion y telemetria sin estado quedan fuera.
if ($LegacySources.Count -gt 0) {
    if (-not $LicData.PSObject.Properties['SecurityEntitlementSummary'] -and $LicData.PSObject.Properties['SecurityPurchaseSummary']) {
        $OldSummary = $LicData.SecurityPurchaseSummary
        $LicData | Add-Member -NotePropertyName 'SecurityEntitlementSummary' -NotePropertyValue ([PSCustomObject]@{
            CoreE5Assigned = $OldSummary.CoreE5Assigned
            CoreE3Assigned = $OldSummary.CoreE3Assigned
            SecurityRelevantSkus = $OldSummary.SecurityRelevantPaidSkus
            TopSecurityEntitlements = @($OldSummary.TopSecurityPurchases)
            Notes = @('Migrado desde schema v3; asignaciones por SKU, no usuarios unicos ni gasto.')
        }) -Force
    }
    if ($AdoptData -and $AdoptData.Entra) {
        Copy-CanonicalProperty -Object $AdoptData.Entra.MFA -Target 'PctCapable' -Source 'PctRegistered'
        $LegacyCa = $AdoptData.Entra.ConditionalAccess
        Copy-CanonicalProperty -Object $LegacyCa -Target 'BroadScopePolicyDetected' -Source 'HasAllUsersPolicy'
        Copy-CanonicalProperty -Object $LegacyCa -Target 'LegacyAuthBlockPolicyDetected' -Source 'LegacyAuthBlocked'
        Copy-CanonicalProperty -Object $LegacyCa -Target 'RoleTargetedMfaPolicyDetected' -Source 'AdminMfaEnforced'
        Copy-CanonicalProperty -Object $LegacyCa -Target 'PoliciesWithExclusions' -Source 'WithExclusions'
        if ($LegacyCa -and -not $LegacyCa.PSObject.Properties['AssessmentLimitation']) {
            $LegacyCa | Add-Member -NotePropertyName 'AssessmentLimitation' -NotePropertyValue 'Migrado desde v3: señales de diseño; no se conserva la cobertura licenciada inferida.' -Force
        }
        $LegacyPim = $AdoptData.Entra.PIM
        if ($LegacyPim -and -not $LegacyPim.PSObject.Properties['AssessmentLimitation']) {
            $LegacyPim | Add-Member -NotePropertyName 'AssessmentLimitation' -NotePropertyValue 'Datos v3: asignaciones agregadas; el reporte v4 no expone detalle de principals.' -Force
        }
    }
    foreach ($WorkloadName in @('MDE','MDO','MDA','MDI')) {
        $Workload = if ($AdoptData) { $AdoptData.$WorkloadName } else { $null }
        if ($Workload) {
            $Workload | Add-Member -NotePropertyName 'TelemetryStatus' -NotePropertyValue 'legacy-unverified' -Force
            foreach ($Metric in @('DevicesOnboarded','UniqueUsersObserved','EmailsProcessedWindow','PhishingDetected','UniqueApps','EventsWindow','DCsMonitored','LogonEventsWindow')) {
                $Workload | Add-Member -NotePropertyName $Metric -NotePropertyValue $null -Force
            }
        }
    }
    if ($AdoptData -and $AdoptData.Intune) {
        $AdoptData.Intune | Add-Member -NotePropertyName 'TelemetryStatus' -NotePropertyValue 'legacy-unverified' -Force
        foreach ($Metric in @('DevicesEnrolled','CompliancePct','NonCompliant','StaleDevices','StaleThresholdDays')) {
            $AdoptData.Intune | Add-Member -NotePropertyName $Metric -NotePropertyValue $null -Force
        }
    }
    if ($AdoptData -and $AdoptData.Copilot) {
        $AdoptData.Copilot | Add-Member -NotePropertyName 'TelemetryStatus' -NotePropertyValue 'legacy-unverified' -Force
        foreach ($Metric in @('EnabledUsers30d','ActiveUsers30d','AdoptionPct')) {
            $AdoptData.Copilot | Add-Member -NotePropertyName $Metric -NotePropertyValue $null -Force
        }
    }
    if ($ScoreData) {
        foreach ($Recommendation in @($ScoreData.AllRecommendations) + @($ScoreData.TopRecommendations)) {
            if ($Recommendation) { $Recommendation | Add-Member -NotePropertyName 'DataQuality' -NotePropertyValue 'legacy' -Force }
        }
    }
}

# ── Enriquecer AdoptData con SecureScoreControls ──────────────────────────
if ($AdoptData -and $ScoreData -and $ScoreData.AllRecommendations) {
    $SvcMap = @{ "MDO"="MDO"; "MCAS"="MDA"; "MDATP"="MDE"; "Azure ATP"="MDI" }
    foreach ($Svc in $SvcMap.Keys) {
        $Key  = $SvcMap[$Svc]
        $DataProperty = $AdoptData.PSObject.Properties[$Key]
        $Data = if ($DataProperty) { $DataProperty.Value } else { $null }
        if ($Data -and -not $Data.PSObject.Properties['SecureScoreControls']) {
            $Ctrls = @($ScoreData.AllRecommendations | Where-Object { $_.Service -eq $Svc })
            if ($Ctrls.Count -gt 0) {
                $En = @($Ctrls | Where-Object { $_.ImplementationStatus -eq 'Implemented' }).Count
                $Pa = @($Ctrls | Where-Object { $_.CurrentScore -gt 0 -and $_.CurrentScore -lt $_.MaxScore }).Count
                $Data | Add-Member -NotePropertyName 'SecureScoreControls' -NotePropertyValue ([PSCustomObject]@{
                    Total=$Ctrls.Count; FullyEnabled=$En; Partial=$Pa; NotImplemented=($Ctrls.Count-$En-$Pa)
                }) -Force
            }
        }
    }
}

# Capturar únicamente nombres de scopes antes de minimizar ModuleStatus. No se
# conservan tokens, principals ni detalles de autenticación en el manifest.
$ManifestScopes = @()
if ($AdoptData -and $AdoptData.ModuleStatus) {
    $GraphStatusProperty = $AdoptData.ModuleStatus.PSObject.Properties['GraphConnection']
    $DetailsProperty = if ($GraphStatusProperty -and $GraphStatusProperty.Value) { $GraphStatusProperty.Value.PSObject.Properties['details'] } else { $null }
    $ScopesProperty = if ($DetailsProperty -and $DetailsProperty.Value) { $DetailsProperty.Value.PSObject.Properties['scopes'] } else { $null }
    if ($ScopesProperty -and $ScopesProperty.Value) {
        $ManifestScopes = @($ScopesProperty.Value | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    }
}

# ── Minimizar payload y sanitizar estado de recoleccion ─────────────────────
# El HTML necesita saber si un modulo fue success/warning/error, pero nunca debe
# recibir URIs, mensajes crudos, cuentas ni detalles de excepciones.
$TenantFingerprintInternal = if ($LicData.PSObject.Properties['TenantFingerprint'] -and $LicData.TenantFingerprint) {
    [string]$LicData.TenantFingerprint
} elseif ($LicData.PSObject.Properties['TenantId'] -and $LicData.TenantId) {
    Get-TenantFingerprint -Value ([string]$LicData.TenantId)
} else { "unknown" }
foreach ($LegacyProperty in @('Mode','InactiveDays','Departments','Capacity','Adoption','Waste','Duplicates','AssignmentMethods','SecurityPurchaseSummary')) {
    if ($LicData.PSObject.Properties[$LegacyProperty]) { $LicData.PSObject.Properties.Remove($LegacyProperty) }
}
if ($AdoptData -and $AdoptData.PSObject.Properties['TenantWideProtection']) { $AdoptData.PSObject.Properties.Remove('TenantWideProtection') }
if ($AdoptData -and $AdoptData.Entra) {
    if ($AdoptData.Entra.MFA) {
        foreach ($Name in @('PctRegistered','MfaCapable')) {
            if ($AdoptData.Entra.MFA.PSObject.Properties[$Name]) { $AdoptData.Entra.MFA.PSObject.Properties.Remove($Name) }
        }
    }
    if ($AdoptData.Entra.ConditionalAccess) {
        foreach ($Name in @('LicCoveragePct','LicCovered','LicTotal','HasAllUsersPolicy','LegacyAuthBlocked','AdminMfaEnforced','WithExclusions')) {
            if ($AdoptData.Entra.ConditionalAccess.PSObject.Properties[$Name]) { $AdoptData.Entra.ConditionalAccess.PSObject.Properties.Remove($Name) }
        }
    }
    if ($AdoptData.Entra.PIM) {
        foreach ($Name in @('EligibleUsers','ActiveUsers','ActiveSPs','ActiveGroups','ActiveOther','ActiveTotal','PermanentUsers','PermanentSPs','TopPermanentRoles')) {
            if ($AdoptData.Entra.PIM.PSObject.Properties[$Name]) { $AdoptData.Entra.PIM.PSObject.Properties.Remove($Name) }
        }
    }
}
if ($AdoptData) {
    foreach ($WorkloadName in @('MDE','MDO','MDA','MDI','Intune','Copilot')) {
        $WorkloadProperty = $AdoptData.PSObject.Properties[$WorkloadName]
        $Workload = if ($WorkloadProperty) { $WorkloadProperty.Value } else { $null }
        if (-not $Workload) { continue }
        foreach ($Name in @('CoveragePct','UniqueUsersWithDevice','UsersWithLicense','EmailsProcessed30d','Events30d','LogonEvents30d','Alerts30d','Stale30d','LicensedUsers','DCDetails','TopApps')) {
            if ($Workload.PSObject.Properties[$Name]) { $Workload.PSObject.Properties.Remove($Name) }
        }
    }
}
if ($AdoptData -and $AdoptData.ModuleStatus) {
    $StatusSummary = [ordered]@{}
    foreach ($Property in $AdoptData.ModuleStatus.PSObject.Properties) {
        $StatusSummary[$Property.Name] = [ordered]@{
            status  = [string]$Property.Value.status
            message = [string]$Property.Value.message
        }
    }
    $AdoptData.ModuleStatus = [PSCustomObject]$StatusSummary
}
if ($PrivacyProfile -eq 'Shareable') {
    foreach ($DataObject in @($LicData, $AdoptData, $ScoreData)) {
        if (-not $DataObject) { continue }
        foreach ($Name in @('TenantId', 'TenantName', 'TenantDomain', 'TenantFingerprint')) {
            if ($DataObject.PSObject.Properties[$Name]) { $DataObject.PSObject.Properties.Remove($Name) }
        }
    }
}

# ── Findings normalizados y prioridad por riesgo/confianza ─────────────────
$Findings = [System.Collections.Generic.List[object]]::new()
$FindingIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
function Add-FindingIfNew {
    param($Finding)
    if ($Finding -and $FindingIds.Add([string]$Finding.ControlId)) { $Findings.Add($Finding) }
}

$Thresholds = $AssessmentProfile.Thresholds
$Entra = if ($AdoptData) { $AdoptData.Entra } else { $null }
$MfaStatus = Get-ModuleStatusValue -AdoptionData $AdoptData -Name 'MFA_SSPR'
if (-not $MfaStatus -or [string]$MfaStatus.status -ne 'success') {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'EVID-MFA'
    $Evidence = if ($MfaStatus -and $MfaStatus.message) { [string]$MfaStatus.message } else { 'No hubo evidencia verificable de MFA/SSPR.' }
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'EVID-MFA' -Evidence $Evidence -Source 'Evidence')
} elseif ($Entra -and $Entra.MFA -and $null -ne $Entra.MFA.PctCapable -and [double]$Entra.MFA.PctCapable -lt [double]$Thresholds.MfaCapableTargetPct) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-MFA-CAPABLE'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-MFA-CAPABLE' -Evidence ("MFA capable: {0}% sobre población {1}; objetivo del perfil: {2}%." -f $Entra.MFA.PctCapable, $Entra.MFA.Population, $Thresholds.MfaCapableTargetPct))
}

$Ca = if ($Entra) { $Entra.ConditionalAccess } else { $null }
if ($Ca -and $Ca.LegacyAuthBlockPolicyDetected -eq $false) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-CA-LEGACY'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-CA-LEGACY' -Evidence 'No se detectó una política activa con control block para clientes legacy.')
}
if ($Ca -and $Ca.RoleTargetedMfaPolicyDetected -eq $false) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-CA-PRIV-MFA'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-CA-PRIV-MFA' -Evidence 'No se detectó una política MFA dirigida a roles; la señal no demuestra cobertura total.')
}
if ($Ca -and $null -ne $Ca.PoliciesWithExclusions -and [double]$Ca.PoliciesWithExclusions -gt 0) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-CA-EXCLUSIONS'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-CA-EXCLUSIONS' -Evidence ("{0} políticas activas contienen exclusiones." -f $Ca.PoliciesWithExclusions))
}
if ($Ca -and $null -ne $Ca.Enabled -and [double]$Ca.Enabled -eq 0 -and $Entra.SecurityDefaults -and $Entra.SecurityDefaults.Enabled -ne $true) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-BASELINE'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-BASELINE' -Evidence 'No se observaron políticas CA activas ni Security Defaults habilitado.')
}
if ($Entra -and $Entra.RiskyUsers -and $null -ne $Entra.RiskyUsers.High -and [double]$Entra.RiskyUsers.High -ge [double]$Thresholds.RiskyHighReviewAt) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-RISK-HIGH'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-RISK-HIGH' -Evidence ("{0} identidades en estado de riesgo alto." -f $Entra.RiskyUsers.High))
}
if ($Entra -and $Entra.GlobalAdmins -and $null -ne $Entra.GlobalAdmins.Count -and [double]$Entra.GlobalAdmins.Count -ge [double]$Thresholds.GlobalAdminsReviewAt) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-GA-COUNT'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-GA-COUNT' -Evidence ("{0} asignaciones Global Administrator; umbral de revisión: {1}." -f $Entra.GlobalAdmins.Count, $Thresholds.GlobalAdminsReviewAt))
}
if ($Entra -and $Entra.PIM -and $null -ne $Entra.PIM.PermanentAssignments -and [double]$Entra.PIM.PermanentAssignments -ge [double]$Thresholds.PimPermanentReviewAt) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'ENTRA-PIM-PERM'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'ENTRA-PIM-PERM' -Evidence ("{0} asignaciones permanentes; umbral de revisión: {1}." -f $Entra.PIM.PermanentAssignments, $Thresholds.PimPermanentReviewAt))
}

$MdiStatus = Get-ModuleStatusValue -AdoptionData $AdoptData -Name 'MDI'
if ($MdiStatus -and [string]$MdiStatus.status -eq 'success' -and $AdoptData.MDI -and $null -ne $AdoptData.MDI.DCsMonitored -and [double]$AdoptData.MDI.DCsMonitored -eq 0) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'MDI-SENSORS'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'MDI-SENSORS' -Evidence 'La licencia fue detectada, pero Advanced Hunting observó 0 Domain Controllers en la ventana.')
}
$IntuneStatus = Get-ModuleStatusValue -AdoptionData $AdoptData -Name 'Intune'
if ($IntuneStatus -and [string]$IntuneStatus.status -eq 'success' -and $AdoptData.Intune -and $null -ne $AdoptData.Intune.DevicesEnrolled -and [double]$AdoptData.Intune.DevicesEnrolled -eq 0) {
    $Control = Get-CatalogControl -Profile $AssessmentProfile -Id 'INTUNE-ENROLLMENT'
    Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $Control -ControlId 'INTUNE-ENROLLMENT' -Evidence 'Intune está licenciado y Graph confirmó 0 dispositivos administrados.')
}

if ($AdoptData -and $AdoptData.ModuleStatus) {
    $BaseControl = Get-CatalogControl -Profile $AssessmentProfile -Id 'EVID-MODULE'
    foreach ($Property in $AdoptData.ModuleStatus.PSObject.Properties) {
        $Status = [string]$Property.Value.status
        if ($Status -notin @('warning','error','unknown')) { continue }
        if ($Property.Name -eq 'MFA_SSPR' -and $FindingIds.Contains('EVID-MFA')) { continue }
        $DynamicId = "EVID-MODULE-$($Property.Name.ToUpperInvariant())"
        $Severity = if ($Status -eq 'error') { 'High' } else { 'Medium' }
        Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $BaseControl -ControlId $DynamicId -Title "Recuperar evidencia: $($Property.Name)" -Evidence ([string]$Property.Value.message) -Source 'Evidence' -RiskSeverity $Severity -Confidence 'Low')
    }
}

if ($ScoreData -and $ScoreData.AllRecommendations) {
    $SecureScoreControl = Get-CatalogControl -Profile $AssessmentProfile -Id 'MS-SECURESCORE'
    foreach ($Recommendation in @($ScoreData.AllRecommendations)) {
        if ($Recommendation.ImplementationStatus -eq 'Implemented' -or $Recommendation.DataQuality -eq 'invalid' -or $null -eq $Recommendation.Improvement -or [double]$Recommendation.Improvement -le 0) { continue }
        $Gain = [double]$Recommendation.Improvement
        $ThreatText = (@(Get-OptionalPropertyValue -Object $Recommendation -Name 'Threats') -join ' ')
        $Severity = if ($ThreatText -match '(?i)account breach|data exfiltration|elevation of privilege|phishing') { 'High' } else { 'Medium' }
        $Horizon = if ($Gain -ge 5) { 30 } elseif ($Gain -ge 2) { 60 } else { 90 }
        $ControlId = "MS-SS-$([string]$Recommendation.Id)"
        Add-FindingIfNew (New-AssessmentFinding -Profile $AssessmentProfile -Control $SecureScoreControl -ControlId $ControlId -Title ([string]$Recommendation.Title) -Evidence ("Secure Score +{0} pts; servicio {1}; estado {2}." -f $Gain, $Recommendation.Service, $Recommendation.ImplementationStatus) -SecureScoreGain $Gain -Source 'SecureScore' -RiskSeverity $Severity -Confidence 'High' -HorizonDays $Horizon)
    }
}

$Findings = @($Findings | Sort-Object @{ Expression = { switch ($_.PriorityBand) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } }; Ascending = $true }, @{ Expression = { [double]$_.PriorityScore }; Descending = $true }, @{ Expression = { if ($null -ne $_.SecureScoreGain) { [double]$_.SecureScoreGain } else { 0 } }; Descending = $true }, @{ Expression = { [string]$_.ControlId }; Ascending = $true })
$FindingRank = 0
foreach ($Finding in $Findings) {
    $FindingRank++
    $Finding | Add-Member -NotePropertyName 'PriorityRank' -NotePropertyValue $FindingRank -Force
}

# Enriquecer las recomendaciones para que la tabla use el mismo modelo que el plan.
if ($ScoreData) {
    foreach ($Recommendation in @($ScoreData.AllRecommendations) + @($ScoreData.TopRecommendations)) {
        if (-not $Recommendation -or -not $Recommendation.Id) { continue }
        $Finding = $Findings | Where-Object { $_.ControlId -eq "MS-SS-$([string]$Recommendation.Id)" } | Select-Object -First 1
        if (-not $Finding) { continue }
        $Recommendation | Add-Member -NotePropertyName 'AssessmentPriorityRank' -NotePropertyValue $Finding.PriorityRank -Force
        $Recommendation | Add-Member -NotePropertyName 'AssessmentPriorityScore' -NotePropertyValue $Finding.PriorityScore -Force
        $Recommendation | Add-Member -NotePropertyName 'AssessmentPriorityBand' -NotePropertyValue $Finding.PriorityBand -Force
        $Recommendation | Add-Member -NotePropertyName 'AssessmentRiskSeverity' -NotePropertyValue $Finding.RiskSeverity -Force
        $Recommendation | Add-Member -NotePropertyName 'AssessmentConfidence' -NotePropertyValue $Finding.Confidence -Force
        $Recommendation | Add-Member -NotePropertyName 'AssessmentControlId' -NotePropertyValue $Finding.ControlId -Force
    }
}

# ── Historia de tendencia (solo KPIs AGREGADOS, sin PII) ───────────────────
# Se guarda por fingerprint de tenant (no se envia a la Papelera) para mostrar
# la evolucion entre corridas. Cero datos personales: solo numeros de postura.
$Ent = if ($AdoptData) { $AdoptData.Entra } else { $null }
$Kpi = [ordered]@{
    RunId             = $EffectiveRunId
    ProfileVersion    = [string]$AssessmentProfile.ProfileVersion
    Date              = if ($LicData.GeneratedAt) { $LicData.GeneratedAt } else { (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
    ScorePct          = if ($ScoreData -and $ScoreData.Score) { $ScoreData.Score.Pct } else { $null }
    ScoreCurrent      = if ($ScoreData -and $ScoreData.Score) { $ScoreData.Score.Current } else { $null }
    MfaCapablePct     = if ($Ent -and $Ent.MFA) { $Ent.MFA.PctCapable } else { $null }
    CaEnabled         = if ($Ent -and $Ent.ConditionalAccess) { $Ent.ConditionalAccess.Enabled } else { $null }
    LegacyAuthBlockPolicyDetected = if ($Ent -and $Ent.ConditionalAccess -and $Ent.ConditionalAccess.PSObject.Properties['LegacyAuthBlockPolicyDetected']) { [bool]$Ent.ConditionalAccess.LegacyAuthBlockPolicyDetected } else { $null }
    GlobalAdmins      = if ($Ent -and $Ent.GlobalAdmins) { $Ent.GlobalAdmins.Count } else { $null }
    RiskyHigh         = if ($Ent -and $Ent.RiskyUsers) { $Ent.RiskyUsers.High } else { $null }
    LicensedUsers     = $LicData.TotalLicensedUsers
    EvidenceComplete  = [bool](
        $LicData.Collection -and $LicData.Collection.Status -eq 'success' -and
        $ScoreData -and $ScoreData.Collection -and $ScoreData.Collection.Status -eq 'success' -and
        $AdoptData -and $AdoptData.ModuleStatus -and
        @($AdoptData.ModuleStatus.PSObject.Properties | Where-Object { $_.Value.status -in @('error','unknown') }).Count -eq 0
    )
}
$HistorySuffix = $TenantFingerprintInternal
$HistoryPath = Join-Path $OutputPath "_trend_${HistorySuffix}.json"
$History = @()
if (Test-Path $HistoryPath) {
    try { $History = @(Get-Content $HistoryPath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $History = @() }
}
$History = @($History | Where-Object {
    if ($_.PSObject.Properties['RunId'] -and $_.RunId) { [string]$_.RunId -ne $EffectiveRunId }
    else { [string]$_.Date -ne [string]$Kpi.Date }
})
$History += [PSCustomObject]$Kpi
$History = @($History | Sort-Object { $_.Date } | Select-Object -Last 12)   # ultimas 12 corridas
$History | ConvertTo-Json -Depth 5 | Out-File -FilePath $HistoryPath -Encoding UTF8
Write-Host "[*] Tendencia: $($History.Count) corrida(s) en $([IO.Path]::GetFileName($HistoryPath))" -ForegroundColor Yellow

# ── Frescura de fuentes ────────────────────────────────────────────────────
# Se registra la fecha de cada fuente en meta.Sources. El RunId y fingerprint deben
# coincidir; cualquier override queda visible y solo se admite de forma explicita.
$SourceMeta = [ordered]@{}
$SrcTimes   = @{}
foreach ($Src in @(@{k='lic';p=$LicensingJson}, @{k='adopt';p=$AdoptionJson}, @{k='score';p=$SecureScoreJson})) {
    if ($Src.p -and (Test-Path $Src.p)) {
        $fi = Get-Item $Src.p
        $SrcTimes[$Src.k]   = $fi.LastWriteTime
        $SourceMeta[$Src.k] = [ordered]@{
            File       = $fi.Name
            Timestamp  = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            StaleHours = 0
        }
    }
}
if ($SrcTimes.Count -gt 1) {
    $NewestSrc = ($SrcTimes.Values | Measure-Object -Maximum).Maximum
    foreach ($k in @($SrcTimes.Keys)) {
        $LagH = [math]::Round(($NewestSrc - $SrcTimes[$k]).TotalHours, 1)
        $SourceMeta[$k].StaleHours = $LagH
        if ($LagH -gt 6) {
            Write-Host "[!] Fuente '$k' ($($SourceMeta[$k].File)) es $LagH h mas antigua que la corrida actual: el reporte mezcla corridas distintas" -ForegroundColor Yellow
        }
    }
}

# ── Construir MasterJson (solo agregados) ─────────────────────────
Write-Host "[*] Construyendo MasterJson (solo licenciamiento agregado, sin PII)..." -ForegroundColor Yellow
$ManifestName = "${EffectiveRunId}_audit_manifest.json"
$ManifestPath = Join-Path $OutputPath $ManifestName
$MasterObj = [ordered]@{
    lic   = $LicData
    adopt = $AdoptData
    score = $ScoreData
    trend = $History
    findings = @($Findings)
    profile = [ordered]@{
        Name = [string]$AssessmentProfile.ProfileName
        Version = [string]$AssessmentProfile.ProfileVersion
        SchemaVersion = [string]$AssessmentProfile.SchemaVersion
        RiskModel = $AssessmentProfile.RiskModel
        Thresholds = $AssessmentProfile.Thresholds
    }
    meta  = [ordered]@{
        RunId = $EffectiveRunId
        PrivacyProfile = $PrivacyProfile
        IntegrityStatus = if ($LegacySources.Count -gt 0) { "legacy-migrated" } elseif ($ValidationErrors.Count -gt 0) { "override" } else { "verified" }
        LegacySources = @($LegacySources)
        Sources = $SourceMeta
        AuditManifest = $ManifestName
    }
}
$MasterJson = $MasterObj | ConvertTo-Json -Depth 15 -Compress

# ── Inyectar en template y guardar ───────────────────────────────────────
Write-Host "[*] Inyectando datos en template HTML..." -ForegroundColor Yellow
$template = Get-Content $TemplatePath -Raw -Encoding UTF8

if ($template -notmatch '__REPORT_DATA__') {
    Write-Error "El template no contiene el placeholder __REPORT_DATA__. Use report-template.html v4.2."
}

# Neutralizar </script> y separadores de linea JS antes de inyectar en contexto <script>.
# Todo el payload vive dentro de <script>const D=...</script>; el parser HTML cierra el
# tag ante cualquier "</script>" literal (aunque este dentro de un string JS). Escapamos
# < y > como \u003c / \u003e (escape JSON valido que el motor decodifica de vuelta) para que
# un DisplayName/UPN/departamento malicioso no pueda romper el <script> ni inyectar HTML.
$MasterJson = $MasterJson.
    Replace('<','\u003c').
    Replace('>','\u003e').
    Replace(([string][char]0x2028),'\u2028').
    Replace(([string][char]0x2029),'\u2029')

$html = $template.Replace('__REPORT_DATA__', $MasterJson)

# Resolver nombre de salida
$OutName   = if ($ReportName) { $ReportName } else { "${EffectiveRunId}_M365_Security_Report.html" }
if (-not $OutName.EndsWith('.html')) { $OutName += '.html' }
$OutFile   = Join-Path $OutputPath $OutName

# Escribir UTF-8 sin BOM
[System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))

# Manifest separado para auditoría y reproducibilidad. Incluye hashes, versiones,
# scopes nominales, estados sanitizados y findings; nunca tokens ni objetos de usuario.
$ManifestSources = [System.Collections.Generic.List[object]]::new()
foreach ($Source in @(
    @{ Name = 'licensing'; Path = $LicensingJson; Data = $LicData },
    @{ Name = 'adoption'; Path = $AdoptionJson; Data = $AdoptData },
    @{ Name = 'secureScore'; Path = $SecureScoreJson; Data = $ScoreData }
)) {
    if (-not $Source.Path -or -not (Test-Path -LiteralPath $Source.Path) -or -not $Source.Data) { continue }
    $Collection = if ($Source.Data.PSObject.Properties['Collection']) { $Source.Data.Collection } else { $null }
    $CollectionStatus = Get-OptionalPropertyValue -Object $Collection -Name 'Status'
    $CollectionSource = Get-OptionalPropertyValue -Object $Collection -Name 'Source'
    $CollectionEndpoints = Get-OptionalPropertyValue -Object $Collection -Name 'Endpoints'
    $FailedRequests = Get-OptionalPropertyValue -Object $Collection -Name 'FailedRequests'
    $InvalidControls = Get-OptionalPropertyValue -Object $Collection -Name 'InvalidControls'
    if (-not $CollectionStatus -and $Source.Name -eq 'adoption' -and $Source.Data.ModuleStatus) {
        $AdoptionStatuses = @($Source.Data.ModuleStatus.PSObject.Properties | ForEach-Object { [string]$_.Value.status })
        $CollectionStatus = if (@($AdoptionStatuses | Where-Object { $_ -eq 'error' }).Count -gt 0) { 'error' }
                            elseif (@($AdoptionStatuses | Where-Object { $_ -in @('warning','unknown') }).Count -gt 0) { 'partial' }
                            else { 'success' }
        $CollectionSource = 'ModuleStatus aggregate'
    }
    $ManifestSources.Add([PSCustomObject][ordered]@{
        Name            = $Source.Name
        File            = [IO.Path]::GetFileName($Source.Path)
        Sha256          = Get-FileSha256Lower -Path $Source.Path
        GeneratedAt     = [string]$Source.Data.GeneratedAt
        SchemaVersion   = [string]$Source.Data.SchemaVersion
        ScriptVersion   = [string]$Source.Data.ScriptVersion
        CollectionStatus = if ($CollectionStatus) { [string]$CollectionStatus } else { 'notDeclared' }
        CollectionSource = if ($CollectionSource) { [string]$CollectionSource } else { $null }
        Endpoints       = if ($CollectionEndpoints) { @($CollectionEndpoints | ForEach-Object { [string]$_ }) } else { @() }
        FailedRequests  = $FailedRequests
        InvalidControls = $InvalidControls
    })
}

$Manifest = [ordered]@{
    ManifestVersion = '1.0'
    AssessmentVersion = '4.2'
    RunId = $EffectiveRunId
    GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
    PrivacyProfile = $PrivacyProfile
    IntegrityStatus = $MasterObj.meta.IntegrityStatus
    ContainsUserObjects = $false
    Profile = [ordered]@{
        Name = [string]$AssessmentProfile.ProfileName
        Version = [string]$AssessmentProfile.ProfileVersion
        SchemaVersion = [string]$AssessmentProfile.SchemaVersion
        File = [IO.Path]::GetFileName($ProfilePath)
        Sha256 = Get-FileSha256Lower -Path $ProfilePath
    }
    Sources = @($ManifestSources)
    GrantedScopes = @($ManifestScopes)
    ModuleStatus = if ($AdoptData) { $AdoptData.ModuleStatus } else { $null }
    Findings = @($Findings)
    ControlCatalog = @($AssessmentProfile.ControlCatalog)
    Report = [ordered]@{
        File = [IO.Path]::GetFileName($OutFile)
        Sha256 = Get-FileSha256Lower -Path $OutFile
    }
}
if ($PrivacyProfile -eq 'Internal') { $Manifest.TenantFingerprint = $TenantFingerprintInternal }
$Manifest | ConvertTo-Json -Depth 15 | Out-File -FilePath $ManifestPath -Encoding UTF8

# Restringir lectura al usuario actual (Unix: chmod 600 · Windows: icacls).
# El HTML contiene la postura completa del tenant y no debe quedar legible para
# cualquier usuario local.
foreach ($restricted in @($OutFile, $ManifestPath, $HistoryPath, $LicensingJson, $AdoptionJson, $SecureScoreJson)) {
    if ($restricted) { Protect-Path -Path $restricted }
}

$SizeMB = [math]::Round((Get-Item $OutFile).Length / 1MB, 2)
Write-Host "[OK] Reporte generado: $OutFile ($SizeMB MB)" -ForegroundColor Green
Write-Host "[OK] Manifest de auditoría: $ManifestPath" -ForegroundColor Green

# ── Limpieza de intermedios ────────────────────────────────────────────────
# Objetivo: conservar el HTML depurado y su manifest de auditoría. Se envían a
# la Papelera los CSV/JSON intermedios del run.
if (-not $KeepIntermediates) {
    Write-Host "[*] Enviando datos intermedios (CSV/JSON con datos del tenant) a la Papelera..." -ForegroundColor Yellow
    $toTrash = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @($LicensingJson, $AdoptionJson, $SecureScoreJson)) {
        if ($f) { $toTrash.Add($f) }
    }
    # Hermanos del mismo prefijo de run.
    if ($EffectiveRunId) {
        Get-ChildItem -LiteralPath $OutputPath -Filter "$EffectiveRunId*" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.csv', '.json' -and $_.FullName -ne $ManifestPath } |
            ForEach-Object { $toTrash.Add($_.FullName) }
    }
    $unique = $toTrash | Sort-Object -Unique
    if ($unique) { Move-ToTrash -Path $unique }
    Write-Host "[OK] Quedan HTML depurado y manifest de auditoría (sin PII) en: $OutputPath" -ForegroundColor Green
} else {
    Write-Host "[!] -KeepIntermediates: se conservan los CSV/JSON con datos del tenant en $OutputPath" -ForegroundColor DarkYellow
}

# ── Retencion de reportes historicos ──────────────────────────────────────
# Se conservan los ultimos $RetentionRuns reportes HTML; el resto va a la
# Papelera (recuperable). Con 0 se conserva todo.
if ($RetentionRuns -gt 0) {
    $AllReports = @(Get-ChildItem -LiteralPath $OutputPath -Filter "*_M365_Security_Report.html" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($AllReports.Count -gt $RetentionRuns) {
        $OldReports = @($AllReports | Select-Object -Skip $RetentionRuns)
        Write-Host "[*] Retencion: conservando $RetentionRuns reportes, enviando $($OldReports.Count) antiguos a la Papelera..." -ForegroundColor Yellow
        $RetentionArtifacts = [System.Collections.Generic.List[string]]::new()
        foreach ($OldReport in $OldReports) {
            $RetentionArtifacts.Add($OldReport.FullName)
            if ($OldReport.Name -match '^(.*)_M365_Security_Report\.html$') {
                $OldManifest = Join-Path $OutputPath "$($Matches[1])_audit_manifest.json"
                if (Test-Path -LiteralPath $OldManifest) { $RetentionArtifacts.Add($OldManifest) }
            }
        }
        Move-ToTrash -Path @($RetentionArtifacts)
    }
}

if ($Open) {
    if ($IsMacOS) { & open $OutFile }
    elseif ($IsLinux) { & xdg-open $OutFile }
    else { Start-Process $OutFile }
}
return $OutFile
