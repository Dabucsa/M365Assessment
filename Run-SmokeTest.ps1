#Requires -Version 5.1
<#
.SYNOPSIS
    Ejecuta validaciones offline y, opcionalmente, valida una corrida real v4.
.DESCRIPTION
    Comprueba sintaxis, minimizacion de datos, integridad de fuentes, anonimato,
    CSP, escaping anti-XSS y proteccion CSV sin conectarse a Microsoft Graph.
#>
param(
    [string]$OutputPath = ".\output",
    [switch]$RunFirst
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$script:Pass = 0
$script:Fail = 0
$script:Warn = 0

function Test-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host ("  [FAIL] $Name" + $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor Red
        $script:Fail++
    }
}

function Test-Warn {
    param([string]$Name, [string]$Detail = '')
    Write-Host ("  [WARN] $Name" + $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor Yellow
    $script:Warn++
}

function Get-ForbiddenPropertyPaths {
    param($Value, [string]$Path = 'D')
    $Forbidden = @(
        'TenantId','TenantName','TenantDomain','TenantFingerprint','Waste','Duplicates',
        'Departments','AssignmentMethods','LicCoveragePct','LicCovered','LicTotal',
        'CoveragePct','DCDetails','TopApps','TenantWideProtection','SecurityPurchaseSummary',
        'LegacyAuthBlocked','AdminMfaEnforced','WithExclusions','PermanentUsers'
    )
    $Found = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary] -and $Value -isnot [PSCustomObject]) {
        $Index = 0
        foreach ($Item in $Value) {
            foreach ($Nested in @(Get-ForbiddenPropertyPaths -Value $Item -Path "$Path[$Index]")) { $Found.Add($Nested) }
            $Index++
        }
        return @($Found)
    }
    foreach ($Property in $Value.PSObject.Properties) {
        $ChildPath = "$Path.$($Property.Name)"
        if ($Forbidden -contains $Property.Name) { $Found.Add($ChildPath) }
        foreach ($Nested in @(Get-ForbiddenPropertyPaths -Value $Property.Value -Path $ChildPath)) { $Found.Add($Nested) }
    }
    return @($Found)
}

function Read-ReportPayload {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Html = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $Match = [regex]::Match($Html, '(?s)<script>const D=(.*?);</script>')
    if (-not $Match.Success) { throw "No se encontro el payload JSON." }
    return $Match.Groups[1].Value | ConvertFrom-Json
}

Write-Host "== M365 Assessment v4: smoke test ==" -ForegroundColor Cyan

if ($RunFirst) {
    Write-Host ""
    Write-Host "[*] Ejecutando assessment real..." -ForegroundColor Cyan
    & (Join-Path $ScriptDir 'Invoke-M365SecurityReport.ps1') -OutputPath $OutputPath -All -KeepIntermediates
}

Write-Host ""
Write-Host "-- Sintaxis y superficie de ataque --" -ForegroundColor White
$ParseFailed = [System.Collections.Generic.List[string]]::new()
foreach ($File in @(Get-ChildItem -LiteralPath $ScriptDir -Filter '*.ps1' -File)) {
    $Tokens = $null
    $Errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$Errors)
    if ($Errors.Count -gt 0) { $ParseFailed.Add($File.Name) }
}
Test-Check 'Todos los scripts parsean' ($ParseFailed.Count -eq 0) ($ParseFailed -join ', ')

$CollectorFiles = @(
    (Join-Path $ScriptDir 'Get-M365LicensingData.ps1'),
    (Join-Path $ScriptDir 'Get-M365SecurityAdoption.ps1'),
    (Join-Path $ScriptDir 'Get-M365SecureScore.ps1')
)
$CollectorText = ($CollectorFiles | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join [Environment]::NewLine
$GraphWrites = [regex]::Matches($CollectorText, '(?im)\b(Set|New|Remove|Update|Disable|Enable|Revoke|Reset)-Mg[A-Za-z]+')
Test-Check 'Sin cmdlets Graph de escritura' ($GraphWrites.Count -eq 0)

$ForbiddenCollection = @('userRegistrationDetails','getByIds','getMicrosoft365CopilotUserDetail','UsersCsvPath','DCDetails','TopApps')
$CollectionHits = @($ForbiddenCollection | Where-Object { $CollectorText -match [regex]::Escape($_) })
Test-Check 'Sin endpoints o payloads identificadores legacy' ($CollectionHits.Count -eq 0) ($CollectionHits -join ', ')

$LicensingText = Get-Content -LiteralPath (Join-Path $ScriptDir 'Get-M365LicensingData.ps1') -Raw
$SecureScoreText = Get-Content -LiteralPath (Join-Path $ScriptDir 'Get-M365SecureScore.ps1') -Raw
$UserApiLines = @($LicensingText -split [Environment]::NewLine | Where-Object {
    $_ -match 'graph\.microsoft\.com/v1\.0/users' -and $_ -notmatch '\$count'
})
Test-Check 'Licensing solo usa /users/$count' ($UserApiLines.Count -eq 0)
Test-Check 'Secure Score persiste ranking reproducible' ($SecureScoreText -match 'PriorityRank' -and $SecureScoreText -match 'PriorityBand' -and $SecureScoreText -match 'OrderedRecommendations')

$TemplateText = Get-Content -LiteralPath (Join-Path $ScriptDir 'report-template.html') -Raw
$ProfilePath = Join-Path $ScriptDir 'assessment-profile.json'
$Profile = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
$ControlIds = @($Profile.ControlCatalog | ForEach-Object { [string]$_.Id })
$WeightTotal = [double]$Profile.RiskModel.Weights.RiskSeverity + [double]$Profile.RiskModel.Weights.Confidence + [double]$Profile.RiskModel.Weights.SecureScoreGain + [double]$Profile.RiskModel.Weights.Urgency
Test-Check 'Perfil de assessment usa schema 1.0' ($Profile.SchemaVersion -eq '1.0')
Test-Check 'Catálogo de controles usa IDs únicos' ($ControlIds.Count -eq @($ControlIds | Sort-Object -Unique).Count)
Test-Check 'Pesos del modelo de riesgo suman 100%' ([math]::Abs($WeightTotal - 1.0) -lt 0.0001)
Test-Check 'Template bloquea conexiones externas' ($TemplateText -match "connect-src 'none'")
Test-Check 'Template sin recursos externos' ($TemplateText -notmatch '(?i)<script[^>]+src=|<link[^>]+stylesheet')
Test-Check 'Template evita sinks DOM inseguros' ($TemplateText -notmatch '(?i)innerHTML|document\.write|\beval\s*\(')
Test-Check 'Links externos protegidos' ($TemplateText -match 'noopener noreferrer' -and $TemplateText -match "referrerPolicy='no-referrer'")
Test-Check 'CSV protege formula injection' ($TemplateText -match '\^\[\\t\\r\\n \]\*\[=\+\\-@\]')
Test-Check 'Secure Score conserva desglose por dominio' ($TemplateText -match 'Secure Score por dominio' -and $TemplateText -match 'S\.Categories')
Test-Check 'Licenciamiento identifica producto y fuente' ($TemplateText -match 'Inventario de suscripciones' -and $TemplateText -match '/subscribedSkus')
Test-Check 'Licenciamiento evita vistas redundantes' ($TemplateText -notmatch 'Productos con capacidades de seguridad' -and $TemplateText -match 'Matriz de capacidades')
Test-Check 'Resumen de licencias escala a multiples SKUs' ($TemplateText -match 'ents\.slice\(0,3\)' -and $TemplateText -match 'hiddenProducts' -and $TemplateText -match 'overflow-wrap:anywhere')
Test-Check 'Postura explica calidad de evidencia' ($TemplateText -match 'Cobertura de recolecci.n' -and $TemplateText -match 'no si el control est. bien configurado')
Test-Check 'Recomendaciones exponen ranking y prioridad' ($TemplateText -match 'PriorityRank' -and $TemplateText -match 'Ganancia potencial')
Test-Check 'Template renderiza tendencias y regresiones' ($TemplateText -match 'Evoluci.n y regresiones' -and $TemplateText -match 'Sin regresiones autom.ticas')
Test-Check 'Plan consume findings normalizados' ($TemplateText -match 'FINDINGS\.slice' -and $TemplateText -match 'control-id')
Test-Check 'Guia operacional incluye ciclo, RACI y playbooks' ($TemplateText -match 'Ciclo de madurez' -and $TemplateText -match 'Modelo RACI' -and $TemplateText -match 'Playbooks m.nimos')
Test-Check 'Guia operacional omite ruta de automatizacion' ($TemplateText -notmatch 'Ruta de automatizaci.n segura' -and $TemplateText -notmatch 'Identidad de servicio')

Write-Host ""
Write-Host "-- Renderer offline con fixtures v4 --" -ForegroundColor White
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("m365-assessment-smoke-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
$Run = 'smoke_v4_001'
$Fingerprint = '0123456789abcdef'
$FakeTenant = '11111111-2222-3333-4444-555555555555'

try {
    $Lic = [ordered]@{
        RunId = $Run
        GeneratedAt = '2026-07-11 20:00:00'
        ScriptVersion = '4.0'
        SchemaVersion = '4.0'
        TenantId = $FakeTenant
        TenantFingerprint = $Fingerprint
        TotalTenantUsers = 12
        TotalMembers = 10
        TotalGuests = 2
        TotalLicensedUsers = 9
        SKUs = @([ordered]@{
            FriendlyName = '</script><img src=x onerror=alert(1)>'
            SKU_PartNumber = 'TEST_E5'
            Total = 10
            Assigned = 9
            Unassigned = 1
            PctUsed = 90
            IncludedCategories = 'Entra_ID_P2 | MDE_P2'
        })
        SkuMatrix = @()
        SecurityCategories = @()
        CategoryGroups = @{}
        SecurityEntitlementSummary = [ordered]@{
            CoreE5Assigned = 9
            CoreE3Assigned = 0
            SecurityRelevantSkus = 1
            TopSecurityEntitlements = @([ordered]@{
                FriendlyName = 'Enterprise Mobility + Security E5'
                SKU_PartNumber = 'EMSPREMIUM'
                Family = 'Identity / EMS'
                Assigned = 9
                Total = 10
                IncludedCategories = @('Entra_ID_P2','MDE_P2')
            })
            Notes = @()
        }
        Collection = [ordered]@{ Status = 'success'; Source = 'Microsoft Graph'; ContainsUserObjects = $false }
    }
    $Adopt = [ordered]@{
        RunId = $Run
        GeneratedAt = '2026-07-11 20:01:00'
        ScriptVersion = '4.0'
        SchemaVersion = '4.0'
        TenantId = $FakeTenant
        TenantFingerprint = $Fingerprint
        TotalLicensedUsers = 9
        Entra = [ordered]@{
            ConditionalAccess = [ordered]@{
                Total = 3
                Enabled = 2
                ReportOnly = 1
                Disabled = 0
                BroadScopePolicyDetected = $true
                LegacyAuthBlockPolicyDetected = $false
                RoleTargetedMfaPolicyDetected = $true
                PoliciesWithExclusions = 1
                AssessmentLimitation = 'Senal, no cobertura.'
            }
            SecurityDefaults = [ordered]@{ Enabled = $false }
            GlobalAdmins = [ordered]@{ Count = 4 }
            MFA = [ordered]@{ Capable = 8; TotalUsers = 10; PctCapable = 80; Population = 'members' }
            RiskyUsers = [ordered]@{ TotalAtRisk = 1; High = 1; Medium = 0; Low = 0 }
            PIM = [ordered]@{
                EligibleAssignments = 4
                EligibleRoles = 2
                ActiveAssignments = 3
                ActiveRoles = 2
                PermanentAssignments = 3
                PrincipalDetailCollected = $false
                AssessmentLimitation = 'Asignaciones, no personas.'
            }
        }
        MDE = [ordered]@{
            TelemetryStatus = 'partial'
            DevicesOnboarded = 7
            UniqueUsersObserved = $null
            CoverageStatus = 'notCalculated'
        }
        Purview = [ordered]@{
            Note = 'Secure Score'
            SecureScoreControls = [ordered]@{ Total = 2; FullyEnabled = 1; Partial = 0; NotImplemented = 1; Unknown = 0 }
        }
        ModuleStatus = [ordered]@{
            GraphConnection = [ordered]@{ status = 'success'; message = 'Sesion validada.' }
            ConditionalAccess = [ordered]@{ status = 'success'; message = 'CA leido.' }
            SecurityDefaults = [ordered]@{ status = 'success'; message = 'Baseline leido.' }
            GlobalAdmins = [ordered]@{ status = 'success'; message = 'Conteo agregado.' }
            MFA_SSPR = [ordered]@{ status = 'success'; message = 'Reporte agregado.' }
            RiskyUsers = [ordered]@{ status = 'success'; message = 'Conteos agregados.' }
            PIM = [ordered]@{ status = 'success'; message = 'Asignaciones agregadas.' }
            MDE = [ordered]@{ status = 'warning'; message = 'Una consulta sin evidencia.' }
            Purview = [ordered]@{ status = 'success'; message = 'Secure Score.' }
        }
    }
    $Recommendation = [ordered]@{
        Id = 'test'
        Title = '=HYPERLINK("https://invalid")</script>'
        Category = 'Identity'
        MaxScore = 10
        CurrentScore = 0
        Improvement = 10
        IsImplemented = $false
        ImplementationStatus = 'NotImplemented'
        DataQuality = 'valid'
        Service = 'Entra'
        PriorityRank = 1
        PriorityBand = 'High'
        ImplementationCost = 'Low'
        UserImpact = 'Low'
    }
    $Score = [ordered]@{
        RunId = $Run
        GeneratedAt = '2026-07-11 20:02:00'
        ScriptVersion = '4.0'
        SchemaVersion = '4.0'
        TenantId = $FakeTenant
        TenantFingerprint = $Fingerprint
        Collection = [ordered]@{ Status = 'success' }
        Score = [ordered]@{ Current = 40; Max = 100; Pct = 40; Comparative = [ordered]@{ AllTenants = 50; TotalSeats = 45 } }
        Categories = @([ordered]@{ Category = 'Identity'; Score = 20; MaxScore = 50; PctScore = 40; Controls = 5 })
        Summary = [ordered]@{ TotalControls = 1; Implemented = 0; Partial = 0; NotImplemented = 1; Deprecated = 0 }
        TopRecommendations = @($Recommendation)
        AllRecommendations = @($Recommendation)
    }

    $LicPath = Join-Path $TempRoot ($Run + '_report_data.json')
    $AdoptPath = Join-Path $TempRoot ($Run + '_security_adoption.json')
    $ScorePath = Join-Path $TempRoot ($Run + '_secure_score.json')
    $Lic | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $LicPath -Encoding UTF8
    $Adopt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $AdoptPath -Encoding UTF8
    $Score | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ScorePath -Encoding UTF8

    @([ordered]@{
        RunId = 'smoke_v4_prior'
        ProfileVersion = '2026.07'
        Date = '2026-06-11 20:00:00'
        ScorePct = 50
        ScoreCurrent = 50
        MfaCapablePct = 90
        CaEnabled = 3
        LegacyAuthBlockPolicyDetected = $true
        GlobalAdmins = 3
        RiskyHigh = 0
        LicensedUsers = 8
        EvidenceComplete = $true
    }) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TempRoot "_trend_${Fingerprint}.json") -Encoding UTF8

    $ReportPath = & (Join-Path $ScriptDir 'New-M365Report.ps1') -OutputPath $TempRoot -RunId $Run -LicensingJson $LicPath -AdoptionJson $AdoptPath -SecureScoreJson $ScorePath -KeepIntermediates -RetentionRuns 0
    Test-Check 'Renderer genera HTML v4' (Test-Path -LiteralPath $ReportPath)
    $ManifestPath = Join-Path $TempRoot ($Run + '_audit_manifest.json')
    Test-Check 'Renderer genera manifest de auditoría' (Test-Path -LiteralPath $ManifestPath)

    $Html = Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8
    $Payload = Read-ReportPayload -Path $ReportPath
    $ForbiddenPaths = @(Get-ForbiddenPropertyPaths -Value $Payload)
    Test-Check 'Shareable elimina propiedades sensibles/legacy' ($ForbiddenPaths.Count -eq 0) ($ForbiddenPaths -join ', ')
    Test-Check 'Shareable elimina TenantId literal' ($Html -notmatch [regex]::Escape($FakeTenant))
    Test-Check 'Payload malicioso no cierra script' ($Html -notmatch [regex]::Escape('</script><img src=x onerror=alert(1)>'))
    Test-Check 'HTML conserva CSP offline' ($Html -match "connect-src 'none'")
    Test-Check 'Integridad marcada verified' ($Payload.meta.IntegrityStatus -eq 'verified')
    Test-Check 'Metrica sin evidencia permanece null' ($null -eq $Payload.adopt.MDE.UniqueUsersObserved)
    Test-Check 'Payload conserva ranking Secure Score de origen' ($Payload.score.TopRecommendations[0].PriorityRank -eq 1 -and $Payload.score.TopRecommendations[0].PriorityBand -eq 'High')
    Test-Check 'Payload agrega perfil y findings normalizados' ($Payload.profile.Version -eq '2026.07' -and @($Payload.findings).Count -gt 0)
    Test-Check 'Findings usan IDs estables' (@($Payload.findings.ControlId) -contains 'ENTRA-CA-LEGACY' -and @($Payload.findings.ControlId) -contains 'MS-SS-test')
    $LegacyFinding = $Payload.findings | Where-Object { $_.ControlId -eq 'ENTRA-CA-LEGACY' } | Select-Object -First 1
    $ScoreFinding = $Payload.findings | Where-Object { $_.ControlId -eq 'MS-SS-test' } | Select-Object -First 1
    Test-Check 'Critical exige riesgo base Critical' ($LegacyFinding.PriorityBand -eq 'Critical' -and $ScoreFinding.PriorityBand -ne 'Critical')
    Test-Check 'Ranking prioriza banda antes que score' ($LegacyFinding.PriorityRank -lt $ScoreFinding.PriorityRank)
    Test-Check 'Payload conserva dos corridas de tendencia' (@($Payload.trend).Count -eq 2)

    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $ManifestForbidden = @(Get-ForbiddenPropertyPaths -Value $Manifest -Path 'Manifest')
    Test-Check 'Manifest Shareable no contiene identificadores del tenant' ($ManifestForbidden.Count -eq 0) ($ManifestForbidden -join ', ')
    Test-Check 'Manifest declara ausencia de objetos de usuario' ($Manifest.ContainsUserObjects -eq $false)
    Test-Check 'Manifest conserva hashes de tres fuentes' (@($Manifest.Sources).Count -eq 3 -and @($Manifest.Sources | Where-Object { $_.Sha256 -match '^[a-f0-9]{64}$' }).Count -eq 3)
    $ExpectedReportHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ReportPath).Hash.ToLowerInvariant()
    Test-Check 'Manifest verifica hash del HTML' ($Manifest.Report.Sha256 -eq $ExpectedReportHash)
    Test-Check 'Manifest comparte findings con HTML' (@($Manifest.Findings).Count -eq @($Payload.findings).Count)

    $Node = Get-Command node -ErrorAction SilentlyContinue
    if ($Node) {
        $Scripts = [regex]::Matches($Html, '(?s)<script>(.*?)</script>') | ForEach-Object { $_.Groups[1].Value }
        $JsPath = Join-Path $TempRoot 'report-check.js'
        $Scripts -join [Environment]::NewLine | Set-Content -LiteralPath $JsPath -Encoding UTF8
        & $Node.Source --check $JsPath 2>$null
        Test-Check 'JavaScript pasa node --check' ($LASTEXITCODE -eq 0)
        $RuntimeScript = Join-Path $ScriptDir 'Test-ReportRuntime.js'
        $RuntimeOutput = & $Node.Source $RuntimeScript $ReportPath 2>$null
        $RuntimeOk = $LASTEXITCODE -eq 0
        Test-Check 'JavaScript ejecuta setup completo' $RuntimeOk
        $RuntimeResult = if ($RuntimeOk) { $RuntimeOutput | ConvertFrom-Json } else { $null }
        Test-Check 'Runtime renderiza recomendaciones' ($RuntimeResult -and $RuntimeResult.recommendationRows -gt 0)
        Test-Check 'Runtime normaliza esfuerzo/impacto Unknown' ($RuntimeResult -and $RuntimeResult.unknownEffortLabels -eq 0)
        Test-Check 'Runtime renderiza plan 30/60/90' ($RuntimeResult -and $RuntimeResult.planColumns -eq 3 -and $RuntimeResult.planItems -gt 0)
    } else {
        Test-Warn 'node no disponible' 'se omitio sintaxis JavaScript'
    }

    $Mixed = $Score.PSObject.Copy()
    $Mixed.RunId = 'otra_corrida'
    $MixedPath = Join-Path $TempRoot 'mixed_secure_score.json'
    $Mixed | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $MixedPath -Encoding UTF8
    $MixedRejected = $false
    try {
        & (Join-Path $ScriptDir 'New-M365Report.ps1') -OutputPath $TempRoot -RunId $Run -LicensingJson $LicPath -AdoptionJson $AdoptPath -SecureScoreJson $MixedPath -KeepIntermediates -RetentionRuns 0 2>$null | Out-Null
    } catch { $MixedRejected = $true }
    Test-Check 'Renderer rechaza RunId mezclado' $MixedRejected

    $LegacyPath = Join-Path $TempRoot 'legacy_report_data.json'
    @{ ScriptVersion = '3.0'; TenantId = $FakeTenant; SKUs = @() } | ConvertTo-Json | Set-Content -LiteralPath $LegacyPath -Encoding UTF8
    $LegacyRejected = $false
    try {
        & (Join-Path $ScriptDir 'New-M365Report.ps1') -OutputPath $TempRoot -RunId 'legacy' -LicensingJson $LegacyPath -KeepIntermediates -RetentionRuns 0 2>$null | Out-Null
    } catch { $LegacyRejected = $true }
    Test-Check 'Renderer rechaza schema legacy por defecto' $LegacyRejected

    $InvalidProfile = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $InvalidProfile.RiskModel.Weights.Urgency = 0.2
    $InvalidProfilePath = Join-Path $TempRoot 'invalid-assessment-profile.json'
    $InvalidProfile | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $InvalidProfilePath -Encoding UTF8
    $InvalidProfileRejected = $false
    try {
        & (Join-Path $ScriptDir 'New-M365Report.ps1') -OutputPath $TempRoot -RunId $Run -LicensingJson $LicPath -AdoptionJson $AdoptPath -SecureScoreJson $ScorePath -ProfilePath $InvalidProfilePath -KeepIntermediates -RetentionRuns 0 2>$null | Out-Null
    } catch { $InvalidProfileRejected = $true }
    Test-Check 'Renderer rechaza perfil con pesos inválidos' $InvalidProfileRejected

    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        $Mode = if ($IsMacOS) { (& stat -f '%Lp' $ReportPath).Trim() } else { (& stat -c '%a' $ReportPath).Trim() }
        Test-Check 'HTML restringido a modo 600' ($Mode -eq '600') "modo=$Mode"
        $ManifestMode = if ($IsMacOS) { (& stat -f '%Lp' $ManifestPath).Trim() } else { (& stat -c '%a' $ManifestPath).Trim() }
        Test-Check 'Manifest restringido a modo 600' ($ManifestMode -eq '600') "modo=$ManifestMode"
    }
} finally {
    if (Test-Path -LiteralPath $TempRoot) { Remove-Item -LiteralPath $TempRoot -Recurse -Force }
}

Write-Host ""
Write-Host "-- Corrida real disponible --" -ForegroundColor White
if (Test-Path -LiteralPath $OutputPath) {
    $LatestLic = Get-ChildItem -LiteralPath $OutputPath -Filter '*_report_data.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($LatestLic) {
        $RealLic = Get-Content -LiteralPath $LatestLic.FullName -Raw | ConvertFrom-Json
        if ($RealLic.PSObject.Properties['SchemaVersion'] -and $RealLic.SchemaVersion -eq '4.0') {
            Test-Check 'Corrida real usa schema v4' $true
            Test-Check 'Corrida real declara RunId' (-not [string]::IsNullOrWhiteSpace([string]$RealLic.RunId))
            Test-Check 'Corrida real no contiene objetos de usuario' ($RealLic.Collection.ContainsUserObjects -eq $false)
        } else {
            Test-Warn 'La corrida real mas reciente es legacy' 'genere una corrida v4 antes de evidencia final'
        }
    } else {
        Test-Warn 'No hay report_data.json real' 'use -RunFirst para validar un tenant'
    }
} else {
    Test-Warn 'No existe OutputPath real' $OutputPath
}

$Color = if ($script:Fail -gt 0) { 'Red' } elseif ($script:Warn -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ""
Write-Host "== Resultado: $($script:Pass) PASS, $($script:Fail) FAIL, $($script:Warn) WARN ==" -ForegroundColor $Color
if ($script:Fail -gt 0) { exit 1 }
