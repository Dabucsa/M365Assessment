# Modulos requeridos: Microsoft.Graph.Authentication
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Security Adoption Assessment v1
.DESCRIPTION
    Complemento de Get-M365LicensingData.ps1. Mide el USO REAL de los productos
    de seguridad del tenant consultando:
    - Entra ID P1: Conditional Access, MFA, SSPR
    - Entra ID P2: Risky Users, PIM, Access Reviews
    - MDE: Dispositivos y usuarios observados en telemetria (via KQL)
    - MDO: Correos procesados, phishing bloqueado (via KQL)
    - MDA: Apps cloud monitoreadas (via KQL)
    - MDI: Domain Controllers monitoreados (via KQL)
    - Intune: Dispositivos enrolled, compliance
    - Copilot: Usuarios habilitados y activos mediante reporte agregado

    Detecta automaticamente que licencias tiene el tenant y ejecuta
    solo los modulos correspondientes.
.PARAMETER OutputPath
    Carpeta con los archivos generados por Get-M365LicensingData (default: .\output)
.PARAMETER DeviceStaleDays
    Dias sin check-in para considerar un dispositivo obsoleto (default: 30)
.EXAMPLE
    .\Get-MSSecurityAdoption.ps1
    .\Get-MSSecurityAdoption.ps1 -OutputPath ".\output"
.NOTES
    Requiere consentimiento para permisos de lectura segun los modulos detectados.
    Modulo PowerShell: Microsoft.Graph.Authentication
    Permisos delegados segun modulos:
      - Policy.Read.All (CA)
      - AuditLog.Read.All (MFA/SSPR agregado)
      - Reports.Read.All (Copilot agregado)
      - DeviceManagementManagedDevices.Read.All (Intune)
      - RoleAssignmentSchedule.Read.Directory (PIM)
      - IdentityRiskyUser.Read.All (Risky Users)
      - AccessReview.Read.All (Access Reviews)
      - ThreatHunting.Read.All (Advanced Hunting - MDE/MDO/MDA/MDI)
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
              Las queries KQL de Advanced Hunting son consultas de lectura sobre telemetria existente.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\output",
    [ValidateRange(1, 365)]
    [int]$DeviceStaleDays = 30,
    [ValidateRange(1, 90)]
    [int]$HuntingLookbackDays = 14,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,
    [string]$LicensingJsonPath,
    [string]$SecureScoreJsonPath,
    [switch]$PreserveGraphSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$OnWindowsHost = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }
$HuntingLookbackDays = [Math]::Max(1, $HuntingLookbackDays)
$HuntingWindowLabel = "${HuntingLookbackDays}d"

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

function Write-Skip {
    param([string]$Message)
    Write-Host "  [--] $Message" -ForegroundColor DarkGray
}

$script:GraphFailures = [System.Collections.Generic.List[object]]::new()
$script:ModuleStatus = [ordered]@{}

function Reset-GraphFailures {
    $script:GraphFailures.Clear()
}

function Add-GraphFailure {
    param(
        [string]$Uri,
        [string]$Category,
        [string]$Message
    )

    $script:GraphFailures.Add([ordered]@{
        uri = $Uri
        category = $Category
        message = $Message
    })
}

function Get-GraphFailures {
    return @($script:GraphFailures.ToArray())
}

function Set-ModuleStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        $Details = $null
    )

    $entry = [ordered]@{
        status = $Status
        message = $Message
    }

    if ($null -ne $Details) {
        $entry.details = $Details
    }

    $script:ModuleStatus[$Name] = $entry
}

function Get-ContextTenantId {
    param($Context)

    if ($null -eq $Context) { return '' }

    foreach ($propertyName in @('TenantId', 'Tenant')) {
        $property = $Context.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            return [string]$property.Value
        }
    }

    return ''
}

function Get-ContextScopes {
    param($Context)

    if ($null -eq $Context) { return @() }

    $scopesProperty = $Context.PSObject.Properties['Scopes']
    if (-not $scopesProperty -or -not $scopesProperty.Value) {
        return @()
    }

    return @($scopesProperty.Value | ForEach-Object { [string]$_ })
}

function Test-GraphContextRequirements {
    param(
        $Context,
        [string]$ExpectedTenantId,
        [string[]]$RequiredScopes
    )

    $accountProperty = if ($Context) { $Context.PSObject.Properties['Account'] } else { $null }
    $account = if ($accountProperty) { [string]$accountProperty.Value } else { '' }
    $tenantId = Get-ContextTenantId -Context $Context
    $grantedScopes = @(Get-ContextScopes -Context $Context)
    $missingScopes = @($RequiredScopes | Where-Object { $grantedScopes -notcontains $_ })
    $tenantMatches = (-not $ExpectedTenantId) -or ($tenantId -and $tenantId -eq $ExpectedTenantId)

    return [ordered]@{
        isUsable = [bool]($account -and $tenantMatches -and $missingScopes.Count -eq 0)
        account = $account
        tenantId = $tenantId
        tenantMatches = $tenantMatches
        grantedScopes = @($grantedScopes)
        missingScopes = @($missingScopes)
    }
}

function Invoke-GraphSafe {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [object]$Body,
        [hashtable]$Headers,
        [int]$MaxRetries = 3
    )
    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        try {
            $Params = @{ Method = $Method; Uri = $Uri; ErrorAction = "Stop"; OutputType = "Hashtable" }
            if ($Body) { $Params.Body = $Body; $Params.ContentType = "application/json" }
            if ($Headers) { $Params.Headers = $Headers }
            return Invoke-MgGraphRequest @Params
        } catch {
            $ErrMsg = $_.Exception.Message
            if ($ErrMsg -match "401|403|Forbidden|Unauthorized|Authorization|Insufficient") {
                Add-GraphFailure -Uri $Uri -Category "permission" -Message $ErrMsg
                Write-Warn "Sin permisos para: $Uri"
                return $null
            }
            if ($ErrMsg -match "404|NotFound") {
                Add-GraphFailure -Uri $Uri -Category "notfound" -Message $ErrMsg
                Write-Warn "No disponible: $Uri"
                return $null
            }
            # 400 BadRequest es un error PERMANENTE (request malformado, params o permiso).
            # Reintentar no cambia nada: fallar rapido en vez de esperar el backoff.
            if ($ErrMsg -match "BadRequest|Bad Request") {
                Add-GraphFailure -Uri $Uri -Category "badrequest" -Message $ErrMsg
                Write-Warn "Solicitud invalida (400), no se reintenta: $Uri"
                return $null
            }
            if ($retry -lt $MaxRetries) {
                $Wait = 5 * [math]::Pow(2, $retry - 1)  # 5, 10, 20
                if ($ErrMsg -match "429|Throttl") {
                    try {
                        $RetryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                        if ($RetryAfter -and $RetryAfter -gt 0) { $Wait = [math]::Ceiling($RetryAfter) + 1 }
                        else { $Wait = [math]::Max($Wait, 15) }
                    } catch { $Wait = [math]::Max($Wait, 15) }
                }
                Write-Step "Reintentando ($retry/$MaxRetries) en ${Wait}s..."
                Start-Sleep -Seconds $Wait
            } else {
                Add-GraphFailure -Uri $Uri -Category "request" -Message $ErrMsg
                Write-Warn "Fallo despues de $MaxRetries intentos: $Uri - $ErrMsg"
                return $null
            }
        }
    }
}

# --- KQL: 1 intento, si falla next ---
# Advanced Hunting no justifica reintentos largos.
# Si esta throttleado, mejor continuar con el siguiente modulo.
function Invoke-KQL {
    param(
        [string]$Query,
        [string]$Label = "AdvancedHunting"
    )
    $Body = @{ Query = $Query } | ConvertTo-Json
    try {
        $Params = @{
            Method      = "POST"
            Uri         = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
            Body        = $Body
            ContentType = "application/json"
            ErrorAction = "Stop"
            OutputType  = "Hashtable"
        }
        $Result = Invoke-MgGraphRequest @Params
        if ($Result -and $Result.ContainsKey('results') -and $Result.results) {
            return $Result.results
        }
        return @()
    } catch {
        $ErrMsg = $_.Exception.Message
        $Category = "query"
        if ($ErrMsg -match "429|Throttl") {
            $Category = "throttling"
            Write-Warn "Throttled - saltando query"
        } elseif ($ErrMsg -match "401|403|Forbidden|Unauthorized") {
            $Category = "permission"
            Write-Warn "Sin permisos para Advanced Hunting"
        } else {
            Write-Warn "KQL fallo: $($ErrMsg.Substring(0, [math]::Min(80, $ErrMsg.Length)))"
        }
        Add-GraphFailure -Uri "kql:$Label" -Category $Category -Message $ErrMsg
        return $null
    }
}

function Get-KqlCount {
    param(
        $Rows,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Rows) { return $null }
    $First = @($Rows | Select-Object -First 1)
    if ($First.Count -eq 0 -or $null -eq $First[0]) { return $null }
    $Row = $First[0]
    $Value = if ($Row -is [System.Collections.IDictionary]) {
        if (-not $Row.Contains($Name)) { return $null }
        $Row[$Name]
    } else {
        $Property = $Row.PSObject.Properties[$Name]
        if (-not $Property) { return $null }
        $Property.Value
    }
    if ($null -eq $Value) { return $null }
    try { return [long]$Value } catch { return $null }
}

function Get-AllGraphPages {
    param(
        [string]$Uri,
        [string]$Label = ""
    )
    $All = [System.Collections.Generic.List[object]]::new()
    $NextUri = $Uri
    $PageNum = 0
    while ($NextUri) {
        $Response = Invoke-GraphSafe -Uri $NextUri
        if (-not $Response) { break }
        if ($Response.ContainsKey('value') -and $Response.value) {
            foreach ($Item in $Response.value) { $All.Add($Item) }
        }
        $PageNum++
        # Mostrar progreso cada 10 paginas para APIs con muchos registros
        if ($Label -and ($PageNum % 10 -eq 0)) {
            Write-Host "`r  [*] $Label - pagina $PageNum ($($All.Count) registros)..." -ForegroundColor Yellow -NoNewline
        }
        $NextUri = if ($Response.ContainsKey('@odata.nextLink')) { $Response['@odata.nextLink'] } else { $null }
    }
    if ($Label -and $PageNum -ge 10) { Write-Host "" }  # nueva linea tras progreso
    return $All
}

function Get-BaselineIdentityEvidence {
    $Baseline = @{}

    try {
        Reset-GraphFailures
        $SecDef = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        if ($SecDef -and $SecDef.ContainsKey('isEnabled')) {
            $Baseline.SecurityDefaults = @{ Enabled = [bool]$SecDef.isEnabled }
            Set-ModuleStatus -Name "SecurityDefaults" -Status "success" -Message "Security Defaults leido correctamente."
            Write-OK "Security Defaults: $([bool]$SecDef.isEnabled)"
        } else {
            Set-ModuleStatus -Name "SecurityDefaults" -Status "unknown" -Message "Graph no devolvio evidencia de Security Defaults."
        }
    } catch {
        Set-ModuleStatus -Name "SecurityDefaults" -Status "error" -Message "No se pudo leer Security Defaults."
        Write-Warn "No se pudo leer Security Defaults: $_"
    }

    try {
        Reset-GraphFailures
        $DirRoles = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,roleTemplateId"
        if ($DirRoles.Count -eq 0 -and @(Get-GraphFailures).Count -gt 0) { throw "Graph no devolvio roles de directorio." }
        $GaRole = $DirRoles | Where-Object { $_.roleTemplateId -eq '62e90394-69f5-4237-9190-012177145e10' } | Select-Object -First 1
        if ($GaRole) {
            $GaMembers = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($GaRole.id)/members?`$select=id"
            if (@(Get-GraphFailures).Count -gt 0) { throw "Graph no permitio confirmar miembros de Global Administrator." }
            $Baseline.GlobalAdmins = @{ Count = @($GaMembers).Count }
            Set-ModuleStatus -Name "GlobalAdmins" -Status "success" -Message "Global Administrators contado sin cargar atributos personales."
            Write-OK "Global Admins: $(@($GaMembers).Count)"
        } else {
            Set-ModuleStatus -Name "GlobalAdmins" -Status "unknown" -Message "No se encontro la instancia de rol Global Administrator."
        }
    } catch {
        Set-ModuleStatus -Name "GlobalAdmins" -Status "error" -Message "No se pudo contar Global Administrators."
        Write-Warn "No se pudo contar Global Admins: $_"
    }

    return $Baseline
}

# ============================================================================
# INICIO
# ============================================================================
$ScriptStart = Get-Date

Write-Host ""
Write-Host "  Microsoft 365 Security Adoption Assessment" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host "  Ventana de Advanced Hunting: $HuntingWindowLabel" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
if (-not $OnWindowsHost) { & /bin/chmod 700 $OutputPath }

# ============================================================================
# FASE 1: CONEXION + CARGA DE DATOS PREVIOS
# ============================================================================
Write-Section "Fase 1: Conexion y Deteccion de Capacidades"

# Cargar report_data.json del Script 1
$JsonFile = if ($LicensingJsonPath) {
    if (Test-Path -LiteralPath $LicensingJsonPath) { Get-Item -LiteralPath $LicensingJsonPath }
    else { $null }
} else {
    Get-ChildItem -Path $OutputPath -Filter "*_report_data.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

if (-not $JsonFile) {
    $Hint = if ($LicensingJsonPath) { $LicensingJsonPath } else { $OutputPath }
    Write-Warn "No se encontro report_data.json en '$Hint'. Ejecuta primero Get-M365LicensingData.ps1"
    exit 1
}
Write-OK "Datos de licenciamiento: $($JsonFile.Name)"
$LicData = Get-Content $JsonFile.FullName -Raw | ConvertFrom-Json

# Denominador agregado, usado solo para contexto. No se usa para inferir cobertura
# de Conditional Access ni de workloads cuando Graph no entrega el numerador exacto.
$LicensedCount = if ($LicData.PSObject.Properties['TotalLicensedUsers'] -and $null -ne $LicData.TotalLicensedUsers) {
    [int]$LicData.TotalLicensedUsers
} else { $null }
if ($null -ne $LicensedCount) {
    Write-OK "Licenciados (conteo agregado, sin UPNs): $LicensedCount"
}

# Detectar que licencias tiene el tenant
$TenantCategories = [System.Collections.Generic.HashSet[string]]::new()
if ($LicData.SKUs) {
    foreach ($Sku in $LicData.SKUs) {
        if ($Sku.IncludedCategories) {
            foreach ($Cat in ($Sku.IncludedCategories -split "\s*\|\s*")) {
                if ($Cat) { [void]$TenantCategories.Add($Cat) }
            }
        }
    }
}

$HasEntraP1      = $TenantCategories.Contains("Entra_ID_P1") -or $TenantCategories.Contains("Entra_ID_P2")
$HasEntraP2      = $TenantCategories.Contains("Entra_ID_P2")
$HasEntraGov     = $TenantCategories.Contains("Entra_ID_Governance")
$HasMDE          = $TenantCategories.Contains("MDE_P1") -or $TenantCategories.Contains("MDE_P2")
$HasMDO          = $TenantCategories.Contains("MDO_P1") -or $TenantCategories.Contains("MDO_P2")
$HasMDA          = $TenantCategories.Contains("MDA")
$HasMDI          = $TenantCategories.Contains("MDI")
$HasIntune       = $TenantCategories.Contains("Intune_P1") -or $TenantCategories.Contains("Intune_P2")
$HasCopilot      = $TenantCategories.Contains("Copilot_M365")
$HasPurview      = @($TenantCategories | Where-Object { $_ -like "Purview_*" }).Count -gt 0
$HasAdvHunting   = $HasMDE -or $HasMDO -or $HasMDA -or $HasMDI

Write-Host "`n  Capacidades detectadas:" -ForegroundColor White
Write-Host "    Entra P1:     $(if($HasEntraP1){'SI'}else{'NO'})" -ForegroundColor $(if($HasEntraP1){"Green"}else{"DarkGray"})
Write-Host "    Entra P2:     $(if($HasEntraP2){'SI'}else{'NO'})" -ForegroundColor $(if($HasEntraP2){"Green"}else{"DarkGray"})
Write-Host "    Entra Gov:    $(if($HasEntraGov){'SI'}else{'NO'})" -ForegroundColor $(if($HasEntraGov){"Green"}else{"DarkGray"})
Write-Host "    MDE:          $(if($HasMDE){'SI'}else{'NO'})" -ForegroundColor $(if($HasMDE){"Green"}else{"DarkGray"})
Write-Host "    MDO:          $(if($HasMDO){'SI'}else{'NO'})" -ForegroundColor $(if($HasMDO){"Green"}else{"DarkGray"})
Write-Host "    MDA:          $(if($HasMDA){'SI'}else{'NO'})" -ForegroundColor $(if($HasMDA){"Green"}else{"DarkGray"})
Write-Host "    MDI:          $(if($HasMDI){'SI'}else{'NO'})" -ForegroundColor $(if($HasMDI){"Green"}else{"DarkGray"})
Write-Host "    Purview:      $(if($HasPurview){'SI'}else{'NO'})" -ForegroundColor $(if($HasPurview){"Green"}else{"DarkGray"})
Write-Host "    Intune:       $(if($HasIntune){'SI'}else{'NO'})" -ForegroundColor $(if($HasIntune){"Green"}else{"DarkGray"})
Write-Host "    Copilot:      $(if($HasCopilot){'SI'}else{'NO'})" -ForegroundColor $(if($HasCopilot){"Green"}else{"DarkGray"})
Write-Host "    Adv Hunting:  $(if($HasAdvHunting){'SI'}else{'NO'})" -ForegroundColor $(if($HasAdvHunting){"Green"}else{"DarkGray"})

# Solicitar solo permisos de los workloads detectados. Los reportes agregados de
# authenticationMethods requieren AuditLog.Read.All; no requieren leer metodos
# individuales de usuarios.
$ScopeList = [System.Collections.Generic.List[string]]::new()
$ScopeList.Add("Policy.Read.All")
$ScopeList.Add("RoleManagement.Read.Directory")
if ($HasEntraP1) {
    $ScopeList.Add("AuditLog.Read.All")
}
if ($HasEntraP2) {
    $ScopeList.Add("IdentityRiskyUser.Read.All")
    $ScopeList.Add("RoleAssignmentSchedule.Read.Directory")
}
if ($HasEntraGov) { $ScopeList.Add("AccessReview.Read.All") }
if ($HasIntune) { $ScopeList.Add("DeviceManagementManagedDevices.Read.All") }
if ($HasAdvHunting) { $ScopeList.Add("ThreatHunting.Read.All") }
if ($HasCopilot) { $ScopeList.Add("Reports.Read.All") }
$Scopes = @($ScopeList | Sort-Object -Unique)

Write-Step "Conectando a Microsoft Graph..."
$ManagedSession = $false
try {
    try { $ExistingCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { $ExistingCtx = $null }
    $ExpectedTenantId = [string]$LicData.TenantId
    $ExistingCtxCheck = Test-GraphContextRequirements -Context $ExistingCtx -ExpectedTenantId $ExpectedTenantId -RequiredScopes $Scopes

    if ($ExistingCtxCheck.isUsable) {
        $Context = $ExistingCtx
        Write-OK "Reusando sesion delegada existente"
    } else {
        if ($ExistingCtx -and $ExistingCtxCheck.account) {
            $ReconnectReasons = [System.Collections.Generic.List[string]]::new()
            if (-not $ExistingCtxCheck.tenantMatches -and $ExpectedTenantId) {
                $ReconnectReasons.Add("tenant distinto ($($ExistingCtxCheck.tenantId) != $ExpectedTenantId)")
            }
            if ($ExistingCtxCheck.missingScopes.Count -gt 0) {
                $ReconnectReasons.Add("scopes faltantes: $($ExistingCtxCheck.missingScopes -join ', ')")
            }
            if ($ReconnectReasons.Count -eq 0) {
                $ReconnectReasons.Add('sesion sin contexto util')
            }
            Write-Warn "Sesion existente no cumple requisitos; se abrira una sesion de proceso: $($ReconnectReasons -join ' | ')"
        }

        $ConnectParams = @{
            Scopes = $Scopes
            NoWelcome = $true
            ContextScope = 'Process'
        }
        if ($ExpectedTenantId) { $ConnectParams.TenantId = $ExpectedTenantId }
        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext
        $ManagedSession = $true

        $CurrentCtxCheck = Test-GraphContextRequirements -Context $Context -ExpectedTenantId $ExpectedTenantId -RequiredScopes $Scopes
        if (-not $CurrentCtxCheck.isUsable) {
            $FailureReasons = [System.Collections.Generic.List[string]]::new()
            if (-not $CurrentCtxCheck.tenantMatches -and $ExpectedTenantId) {
                $FailureReasons.Add("tenant distinto ($($CurrentCtxCheck.tenantId) != $ExpectedTenantId)")
            }
            if ($CurrentCtxCheck.missingScopes.Count -gt 0) {
                $FailureReasons.Add("scopes faltantes: $($CurrentCtxCheck.missingScopes -join ', ')")
            }
            if ($FailureReasons.Count -eq 0) {
                $FailureReasons.Add('la sesion devuelta por Graph no quedo utilizable')
            }
            throw "La sesion Graph no cumple requisitos: $($FailureReasons -join ' | ')"
        }

        Write-OK "Sesion delegada de proceso validada"
    }
    Set-ModuleStatus -Name "GraphConnection" -Status "success" -Message "Sesion Graph validada para tenant y scopes requeridos." -Details @{
        tenantFingerprint = [string]$LicData.TenantFingerprint
        managedSession = $ManagedSession
        scopes = @($Scopes)
    }
} catch {
    Set-ModuleStatus -Name "GraphConnection" -Status "error" -Message "No se pudo establecer una sesion Graph valida." -Details @{
        error = [string]$_
        expectedTenantFingerprint = [string]$LicData.TenantFingerprint
    }
    Write-Warn "No se pudo conectar: $_"
    exit 1
}

# Resultado
$ModulesExecuted = [System.Collections.Generic.List[string]]::new()
$Result = @{
    RunId            = [string]$LicData.RunId
    GeneratedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion    = "4.0"
    SchemaVersion    = "4.0"
    TenantId         = $LicData.TenantId
    TenantFingerprint = $LicData.TenantFingerprint
    TotalLicensedUsers = $LicData.TotalLicensedUsers
    AdvancedHuntingLookbackDays = $HuntingLookbackDays
    ModulesExecuted  = $null  # se llena al final
    ModuleStatus     = $null
}

# ============================================================================
# FASE 2: ENTRA ID P1
# ============================================================================
if ($HasEntraP1) {
    Write-Section "Fase 2: Entra ID (Conditional Access, MFA, SSPR)"
    $EntraData = @{}

    # --- Conditional Access Policies (LIGHTWEIGHT: solo select minimo) ---
    Write-Step "Obteniendo politicas de Conditional Access..."
    try {
        Reset-GraphFailures
        # Solo se solicitan estado, condiciones y controles; no se requieren nombres ni IDs.
        $CaPolicies = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=state,conditions,grantControls"
        $CaGraphFailures = @(Get-GraphFailures)
        if ($CaPolicies.Count -eq 0 -and $CaGraphFailures.Count -gt 0) {
            throw "Graph no devolvio evidencia util de Conditional Access."
        }
        $CaEnabled    = @($CaPolicies | Where-Object { $_.state -eq "enabled" })
        $CaReportOnly = @($CaPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
        $CaDisabled   = @($CaPolicies | Where-Object { $_.state -eq "disabled" })

        $AllUsersPolicy = $false
        foreach ($Pol in $CaEnabled) {
            $IncUsers = $Pol.conditions.users.includeUsers
            if ($IncUsers -contains "All") { $AllUsersPolicy = $true; break }
        }

        # Deteccion de bloqueo de autenticacion heredada (legacy auth) entre las politicas activas:
        # la senal canonica es una politica ENABLED que apunta a los protocolos legacy
        # (clientAppTypes = exchangeActiveSync / other) con grantControls = block.
        # PRIVACIDAD: los objetos de politica incluyen conditions.users.include/excludeUsers y
        # include/excludeGroups (GUIDs). AQUI SOLO se leen para derivar SENALES AGREGADAS
        # (cobertura, legacy-auth, #politicas con exclusiones). Ningun identificador de
        # usuario/grupo/exclusion se guarda: el objeto ConditionalAccess de salida es solo conteos.
        $LegacyAuthPolicyDetected = $false
        $CaWithExclusions  = 0
        $RoleTargetedMfaPolicyDetected = $false
        foreach ($Pol in $CaEnabled) {
            $ClientApps    = @($Pol.conditions.clientAppTypes)
            $TargetsLegacy = ($ClientApps -contains 'exchangeActiveSync') -or ($ClientApps -contains 'other')
            $Blocks        = $false
            $RequiresMfa   = $false
            if ($Pol.grantControls) {
                $Bic         = @($Pol.grantControls.builtInControls)
                $Blocks      = ($Bic -contains 'block')
                $RequiresMfa = ($Bic -contains 'mfa') -or [bool]$Pol.grantControls.authenticationStrength
            }
            if ($TargetsLegacy -and $Blocks) { $LegacyAuthPolicyDetected = $true }

            # MFA exigido a admins (senal de DISENO, no solo conteo): politica ENABLED que
            # requiere MFA (o authentication strength) y aplica a roles privilegiados
            # (includeRoles) o a todos (includeUsers = All). Los GUIDs de roles solo se leen
            # para derivar el booleano; no se guardan.
            if ($RequiresMfa) {
                $InclRoles = @($Pol.conditions.users.includeRoles)
                $InclUsers = @($Pol.conditions.users.includeUsers)
                if ($InclRoles.Count -gt 0 -or ($InclUsers -contains 'All')) { $RoleTargetedMfaPolicyDetected = $true }
            }

            # Conteo de politicas con exclusiones (senal de riesgo) — solo se cuenta, no se identifica a nadie.
            $ExUsers  = @($Pol.conditions.users.excludeUsers)
            $ExGroups = @($Pol.conditions.users.excludeGroups)
            if ($ExUsers.Count -gt 0 -or $ExGroups.Count -gt 0) { $CaWithExclusions++ }
        }

        $EntraData.ConditionalAccess = @{
            Total             = $CaPolicies.Count
            Enabled           = $CaEnabled.Count
            ReportOnly        = $CaReportOnly.Count
            Disabled          = $CaDisabled.Count
            BroadScopePolicyDetected = $AllUsersPolicy
            LegacyAuthBlockPolicyDetected = $LegacyAuthPolicyDetected
            RoleTargetedMfaPolicyDetected = $RoleTargetedMfaPolicyDetected
            PoliciesWithExclusions = $CaWithExclusions
            AssessmentConfidence = "limited"
            AssessmentLimitation = "Las senales confirman existencia de politicas, no cobertura efectiva. Apps, condiciones y exclusiones pueden reducir el alcance."
        }
        Write-OK "CA Policies: $($CaPolicies.Count) total ($($CaEnabled.Count) activas, $($CaReportOnly.Count) report-only, $($CaDisabled.Count) deshabilitadas)"
        Write-OK "CA AllUsers policy activa: $AllUsersPolicy"
        $ModulesExecuted.Add("ConditionalAccess")
        if ($CaGraphFailures.Count -gt 0) {
            Set-ModuleStatus -Name "ConditionalAccess" -Status "warning" -Message "Conditional Access devolvio datos parciales o con advertencias de Graph." -Details @{
                policies = $CaPolicies.Count
                enabled = $CaEnabled.Count
                broadScopePolicyDetected = $AllUsersPolicy
                graphFailures = $CaGraphFailures
            }
        } else {
            Set-ModuleStatus -Name "ConditionalAccess" -Status "success" -Message "Conditional Access leido correctamente." -Details @{
                policies = $CaPolicies.Count
                enabled = $CaEnabled.Count
                reportOnly = $CaReportOnly.Count
                disabled = $CaDisabled.Count
                broadScopePolicyDetected = $AllUsersPolicy
                policiesWithExclusions = $CaWithExclusions
            }
        }
    } catch {
        Set-ModuleStatus -Name "ConditionalAccess" -Status "error" -Message "No se pudieron leer las politicas de Conditional Access." -Details @{
            error = [string]$_
            graphFailures = @(Get-GraphFailures)
        }
        Write-Warn "No se pudo obtener CA policies: $_"
    }

    $BaselineIdentity = Get-BaselineIdentityEvidence
    foreach ($Key in $BaselineIdentity.Keys) { $EntraData[$Key] = $BaselineIdentity[$Key] }

    # --- MFA & SSPR Registration ---
    # Solo APIs agregadas. No se consulta el reporte por usuario ni se procesan UPNs.
    # AuditLog.Read.All es el permiso minimo documentado para ambos endpoints.
    $CtxScopes = @((Get-MgContext).Scopes)
    # @() obligatorio: bajo StrictMode, .Count sobre un resultado escalar/nulo de pipeline lanza error
    $MfaScopeMissing = @(@('AuditLog.Read.All') | Where-Object { $CtxScopes -notcontains $_ })
    if ($MfaScopeMissing.Count -gt 0) {
        Write-Warn "MFA/SSPR omitido: el token no incluye $($MfaScopeMissing -join ', ')."
        Write-Warn "Solucion: Disconnect-MgGraph y re-ejecutar aceptando todos los permisos en el login."
        Set-ModuleStatus -Name "MFA_SSPR" -Status "skipped" -Message "Scopes faltantes en el token: $($MfaScopeMissing -join ', ')." -Details @{ missingScopes = $MfaScopeMissing }
    } else {
        Write-Step "Obteniendo estado de registro de MFA y SSPR..."
        try {
            Reset-GraphFailures
            # --- MODO AGREGADO: APIs de resumen, sin identidades ---
            $AuthPopulation = "members"
            $FeatureReport = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByFeature(includedUserTypes='member',includedUserRoles='all')"
            $MethodReport  = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByMethod(includedUserTypes='member',includedUserRoles='all')"

            # Algunos tenants devuelven 400 para el filtro member aunque el contrato
            # lo documenta. Fallback explicito a all: se conserva la poblacion para
            # que el reporte no la confunda con usuarios licenciados.
            if (-not $FeatureReport) {
                $AuthPopulation = "all"
                $FeatureReport = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByFeature(includedUserTypes='all',includedUserRoles='all')"
                $MethodReport  = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByMethod(includedUserTypes='all',includedUserRoles='all')"
            }

            if ($FeatureReport -and $FeatureReport.ContainsKey('totalUserCount')) {
                $TotalAuthUsers = [int]$FeatureReport.totalUserCount
                $MfaCapable = 0; $SsprRegistered = 0; $SsprEnabled = 0

                if ($FeatureReport.userRegistrationFeatureCounts) {
                    foreach ($F in $FeatureReport.userRegistrationFeatureCounts) {
                        switch ($F.feature) {
                            "mfaCapable"     { $MfaCapable     = [int]$F.userCount }
                            "ssprRegistered" { $SsprRegistered = [int]$F.userCount }
                            "ssprEnabled"    { $SsprEnabled    = [int]$F.userCount }
                        }
                    }
                }

                $MfaPct  = if ($TotalAuthUsers -gt 0) { [math]::Round(($MfaCapable / $TotalAuthUsers) * 100, 1) } else { 0 }
                $SsprPct = if ($TotalAuthUsers -gt 0) { [math]::Round(($SsprRegistered / $TotalAuthUsers) * 100, 1) } else { 0 }

                $EntraData.MFA = @{
                    Capable          = $MfaCapable
                    NotCapable       = $TotalAuthUsers - $MfaCapable
                    TotalUsers       = $TotalAuthUsers
                    PctCapable       = $MfaPct
                    Population       = $AuthPopulation
                    Source           = "usersRegisteredByFeature"
                }
                $EntraData.SSPR = @{
                    Registered       = $SsprRegistered
                    NotRegistered    = $TotalAuthUsers - $SsprRegistered
                    Enabled          = $SsprEnabled
                    TotalUsers       = $TotalAuthUsers
                    PctRegistered    = $SsprPct
                    Population       = $AuthPopulation
                    Source           = "usersRegisteredByFeature"
                }
                Write-OK "MFA:  $MfaCapable/$TotalAuthUsers usuarios ($AuthPopulation) capable ($MfaPct%)"
                Write-OK "SSPR: $SsprRegistered/$TotalAuthUsers usuarios ($AuthPopulation) registrados ($SsprPct%)"

                # Metodos de autenticacion desde API agregada
                if ($MethodReport -and $MethodReport.userRegistrationMethodCounts) {
                    $MethodCounts = @{ Authenticator = 0; PhoneAuth = 0; FIDO2 = 0; Email = 0; WHfB = 0; PasswordlessRegistrations = 0 }
                    foreach ($M in $MethodReport.userRegistrationMethodCounts) {
                        switch ($M.authenticationMethod) {
                            "microsoftAuthenticatorPush"         { $MethodCounts.Authenticator = [int]$M.userCount }
                            "mobilePhone"                        { $MethodCounts.PhoneAuth     = [int]$M.userCount }
                            "fido2SecurityKey"                    { $MethodCounts.FIDO2         = [int]$M.userCount }
                            "email"                              { $MethodCounts.Email          = [int]$M.userCount }
                            "windowsHelloForBusiness"            { $MethodCounts.WHfB           = [int]$M.userCount }
                            "microsoftAuthenticatorPasswordless" { $MethodCounts.PasswordlessRegistrations += [int]$M.userCount }
                            "passKeyDeviceBound"                 { $MethodCounts.PasswordlessRegistrations += [int]$M.userCount }
                            "passKeySynced"                      { $MethodCounts.PasswordlessRegistrations += [int]$M.userCount }
                        }
                    }
                    $EntraData.AuthMethods = $MethodCounts
                    Write-OK "Metodos ($AuthPopulation): Auth=$($MethodCounts.Authenticator), Phone=$($MethodCounts.PhoneAuth), FIDO2=$($MethodCounts.FIDO2), WHfB=$($MethodCounts.WHfB)"
                }

                $ModulesExecuted.Add("MFA_SSPR")
                $MfaGraphFailures = @(Get-GraphFailures)
                if ($MfaGraphFailures.Count -gt 0) {
                    Set-ModuleStatus -Name "MFA_SSPR" -Status "warning" -Message "MFA y SSPR se calcularon con advertencias de Graph en modo agregado." -Details @{
                        totalUsers = $TotalAuthUsers
                        mfaCapablePct = $MfaPct
                        ssprPct = $SsprPct
                        population = $AuthPopulation
                        graphFailures = $MfaGraphFailures
                    }
                } else {
                    Set-ModuleStatus -Name "MFA_SSPR" -Status "success" -Message "MFA y SSPR leidos correctamente en modo agregado." -Details @{
                        totalUsers = $TotalAuthUsers
                        mfaCapablePct = $MfaPct
                        ssprPct = $SsprPct
                        population = $AuthPopulation
                    }
                }
            } else {
                Set-ModuleStatus -Name "MFA_SSPR" -Status "warning" -Message "No se obtuvieron datos de MFA/SSPR desde Graph." -Details @{
                    graphFailures = @(Get-GraphFailures)
                    licensedUsersContext = $LicensedCount
                }
                Write-Warn "No se obtuvieron datos de registro de MFA/SSPR"
            }
        } catch {
            Set-ModuleStatus -Name "MFA_SSPR" -Status "error" -Message "No se pudo obtener el estado de MFA/SSPR." -Details @{
                error = [string]$_
                graphFailures = @(Get-GraphFailures)
            }
            Write-Warn "No se pudo obtener estado de MFA/SSPR: $_"
        }
    }  # fin pre-flight de scopes MFA/SSPR

    $Result.Entra = $EntraData
} else {
    Set-ModuleStatus -Name "ConditionalAccess" -Status "skipped" -Message "Modulo omitido: Entra ID P1 no detectado en licenciamiento."
    Set-ModuleStatus -Name "MFA_SSPR" -Status "skipped" -Message "Modulo omitido: Entra ID P1 no detectado en licenciamiento."
    $Result.Entra = Get-BaselineIdentityEvidence
    Write-Skip "Entra ID P1 no detectado - CA y MFA/SSPR no aplican; baseline universal recolectado"
}

# ============================================================================
# FASE 3: ENTRA ID P2
# ============================================================================
if ($HasEntraP2) {
    Write-Section "Fase 3: Entra ID P2 (Risky Users, PIM, Access Reviews)"
    if (-not $Result.Entra) { $Result.Entra = @{} }

    # --- Risky Users (solo conteo, no paginar todos) ---
    Write-Step "Obteniendo conteo de usuarios riesgosos..."
    try {
        Reset-GraphFailures
        $CountHeaders = @{ ConsistencyLevel = 'eventual' }
        $RiskyHighResp   = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'high' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1&`$select=id" -Method GET -Headers $CountHeaders
        $RiskyMediumResp = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'medium' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1&`$select=id" -Method GET -Headers $CountHeaders
        $RiskyLowResp    = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'low' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1&`$select=id" -Method GET -Headers $CountHeaders

        if (-not $RiskyHighResp -or -not $RiskyMediumResp -or -not $RiskyLowResp) {
            throw "Graph no devolvio los tres conteos de Risky Users; no se publicaran ceros parciales."
        }
        foreach ($RiskResponse in @($RiskyHighResp, $RiskyMediumResp, $RiskyLowResp)) {
            if ($RiskResponse -and -not $RiskResponse.ContainsKey('@odata.count')) {
                throw "Graph no devolvio @odata.count para Risky Users; no se publicara un conteo parcial."
            }
        }
        $RiskyHigh   = if ($RiskyHighResp) { [int]$RiskyHighResp['@odata.count'] } else { 0 }
        $RiskyMedium = if ($RiskyMediumResp) { [int]$RiskyMediumResp['@odata.count'] } else { 0 }
        $RiskyLow    = if ($RiskyLowResp) { [int]$RiskyLowResp['@odata.count'] } else { 0 }
        $RiskyTotal  = $RiskyHigh + $RiskyMedium + $RiskyLow

        $Result.Entra.RiskyUsers = @{
            TotalAtRisk          = $RiskyTotal
            High                 = $RiskyHigh
            Medium               = $RiskyMedium
            Low                  = $RiskyLow
        }
        $RiskyColor = if ($RiskyHigh -gt 0) { "Red" } elseif ($RiskyMedium -gt 0) { "Yellow" } else { "Green" }
        Write-Host "  [OK] Usuarios riesgosos: $RiskyTotal (High:$RiskyHigh, Medium:$RiskyMedium, Low:$RiskyLow)" -ForegroundColor $RiskyColor
        $ModulesExecuted.Add("RiskyUsers")
        $RiskyGraphFailures = @(Get-GraphFailures)
        if ($RiskyGraphFailures.Count -gt 0) {
            Set-ModuleStatus -Name "RiskyUsers" -Status "warning" -Message "Risky Users devolvio datos parciales o con advertencias de Graph." -Details @{
                totalAtRisk = $RiskyTotal
                graphFailures = $RiskyGraphFailures
            }
        } else {
            Set-ModuleStatus -Name "RiskyUsers" -Status "success" -Message "Risky Users leido correctamente." -Details @{
                totalAtRisk = $RiskyTotal
                high = $RiskyHigh
                medium = $RiskyMedium
                low = $RiskyLow
            }
        }
    } catch {
        Set-ModuleStatus -Name "RiskyUsers" -Status "error" -Message "No se pudo obtener Risky Users." -Details @{
            error = [string]$_
            graphFailures = @(Get-GraphFailures)
        }
        Write-Warn "No se pudo obtener usuarios riesgosos: $_"
    }

    # --- PIM: Roles elegibles ---
    Write-Step "Obteniendo roles de PIM..."
    try {
        Reset-GraphFailures
        # No se solicitan principalId ni objetos de directorio. El assessment mide
        # asignaciones y roles, suficientes para postura sin cargar identidades.
        $PimEligible = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=roleDefinitionId,startDateTime,endDateTime,memberType"
        $PimActive   = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$select=roleDefinitionId,assignmentType,startDateTime,endDateTime,memberType"
        if ($PimEligible.Count -eq 0 -and $PimActive.Count -eq 0 -and @(Get-GraphFailures).Count -gt 0) {
            throw "Graph no devolvio evidencia util de PIM."
        }

        # Contar roles unicos
        $EligibleRoles  = @($PimEligible | ForEach-Object { $_.roleDefinitionId } | Sort-Object -Unique).Count
        $ActiveRoles    = @($PimActive | ForEach-Object { $_.roleDefinitionId } | Sort-Object -Unique).Count

        # Permanentes (Assigned sin fecha de fin)
        $TrulyPermanent = @($PimActive | Where-Object {
            $_.assignmentType -eq 'Assigned' -and (-not $_.endDateTime -or [string]::IsNullOrEmpty($_.endDateTime))
        })

        $Result.Entra.PIM = @{
            EligibleAssignments  = $PimEligible.Count
            EligibleRoles        = $EligibleRoles
            ActiveAssignments    = $PimActive.Count
            ActiveRoles          = $ActiveRoles
            PermanentAssignments = $TrulyPermanent.Count
            PrincipalDetailCollected = $false
            AssessmentLimitation = "Los conteos representan asignaciones, no personas unicas; no se resolvieron principals."
        }
        Write-OK "PIM: $($PimEligible.Count) asignaciones elegibles en $EligibleRoles roles"
        Write-OK "PIM: $($PimActive.Count) asignaciones activas; $($TrulyPermanent.Count) permanentes"
        $ModulesExecuted.Add("PIM")
        $PimGraphFailures = @(Get-GraphFailures)
        if ($PimGraphFailures.Count -gt 0) {
            Set-ModuleStatus -Name "PIM" -Status "warning" -Message "PIM devolvio datos parciales o con advertencias de Graph." -Details @{
                eligibleAssignments = $PimEligible.Count
                activeAssignments = $PimActive.Count
                permanentAssignments = $TrulyPermanent.Count
                graphFailures = $PimGraphFailures
            }
        } else {
            Set-ModuleStatus -Name "PIM" -Status "success" -Message "PIM leido correctamente." -Details @{
                eligibleAssignments = $PimEligible.Count
                activeAssignments = $PimActive.Count
                permanentAssignments = $TrulyPermanent.Count
            }
        }
    } catch {
        Set-ModuleStatus -Name "PIM" -Status "error" -Message "No se pudo obtener datos de PIM." -Details @{
            error = [string]$_
            graphFailures = @(Get-GraphFailures)
        }
        Write-Warn "No se pudo obtener datos de PIM: $_"
    }

} else {
    Set-ModuleStatus -Name "RiskyUsers" -Status "notApplicable" -Message "Entra ID P2 no detectado en licenciamiento."
    Set-ModuleStatus -Name "PIM" -Status "notApplicable" -Message "Entra ID P2 no detectado en licenciamiento."
    Write-Skip "Entra ID P2 no detectado - Risky Users y PIM no aplican"
}

# --- Access Reviews: depende de Governance, no de P2 ---
if ($HasEntraGov) {
    if (-not $Result.Entra) { $Result.Entra = @{} }
        Write-Step "Obteniendo Access Reviews..."
        try {
            Reset-GraphFailures
            # @() ensures $Reviews is always an array even if Get-AllGraphPages returns empty (StrictMode safety)
            $Reviews = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?`$select=id,status")
            if ($Reviews.Count -eq 0 -and @(Get-GraphFailures).Count -gt 0) { throw "Graph no devolvio evidencia util de Access Reviews." }
            $ReviewsActive = @($Reviews | Where-Object { $_.status -eq "InProgress" }).Count
            $ReviewsCompleted = @($Reviews | Where-Object { $_.status -eq "Completed" }).Count

            $Result.Entra.AccessReviews = @{
                Total     = $Reviews.Count
                Active    = $ReviewsActive
                Completed = $ReviewsCompleted
            }
            Write-OK "Access Reviews: $($Reviews.Count) total ($ReviewsActive activas, $ReviewsCompleted completadas)"
            $ModulesExecuted.Add("AccessReviews")
            $AccessReviewFailures = @(Get-GraphFailures)
            if ($AccessReviewFailures.Count -gt 0) {
                Set-ModuleStatus -Name "AccessReviews" -Status "warning" -Message "Access Reviews devolvio datos parciales o con advertencias de Graph." -Details @{
                    total = $Reviews.Count
                    active = $ReviewsActive
                    completed = $ReviewsCompleted
                    graphFailures = $AccessReviewFailures
                }
            } else {
                Set-ModuleStatus -Name "AccessReviews" -Status "success" -Message "Access Reviews leido correctamente." -Details @{
                    total = $Reviews.Count
                    active = $ReviewsActive
                    completed = $ReviewsCompleted
                }
            }
        } catch {
            Set-ModuleStatus -Name "AccessReviews" -Status "error" -Message "No se pudieron obtener Access Reviews." -Details @{
                error = [string]$_
                graphFailures = @(Get-GraphFailures)
            }
            Write-Warn "No se pudo obtener Access Reviews: $_"
        }
} else {
    Set-ModuleStatus -Name "AccessReviews" -Status "notApplicable" -Message "Entra Governance no detectado en licenciamiento."
}

# ============================================================================
# FASE 4: ADVANCED HUNTING (MDE, MDO, MDA, MDI)
# ============================================================================
foreach ($Workload in @(
    @{ Name = 'MDE'; Licensed = $HasMDE },
    @{ Name = 'MDO'; Licensed = $HasMDO },
    @{ Name = 'MDA'; Licensed = $HasMDA },
    @{ Name = 'MDI'; Licensed = $HasMDI }
)) {
    if (-not $Workload.Licensed) {
        Set-ModuleStatus -Name $Workload.Name -Status "notApplicable" -Message "$($Workload.Name) no detectado en licenciamiento."
    }
}

if ($HasAdvHunting) {
    Write-Section "Fase 4: Advanced Hunting (MDE, MDO, MDA, MDI)"

    # Verificar acceso a Advanced Hunting con una query generica (1 solo intento)
    Write-Step "Verificando acceso a Advanced Hunting..."
    $KQLAvailable = $false
    try {
        $TestBody = @{ Query = "AlertInfo | where Timestamp > ago(1d) | summarize Records=count()" } | ConvertTo-Json
        $TestResult = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
            -Body $TestBody -ContentType "application/json" -ErrorAction Stop -OutputType Hashtable
        $KQLAvailable = $true
        Write-OK "Advanced Hunting disponible"
    } catch {
        # No disponible — E3 sin Defender, sin permisos, o sin licencia
    }

    if (-not $KQLAvailable) {
        Write-Warn "Advanced Hunting no disponible (requiere M365 Defender habilitado y permiso ThreatHunting.Read.All)"
        Write-Skip "Saltando modulos MDE, MDO, MDA, MDI via KQL"
        foreach ($Workload in @(
            @{ Name = 'MDE'; Licensed = $HasMDE },
            @{ Name = 'MDO'; Licensed = $HasMDO },
            @{ Name = 'MDA'; Licensed = $HasMDA },
            @{ Name = 'MDI'; Licensed = $HasMDI }
        )) {
            if ($Workload.Licensed) {
                Set-ModuleStatus -Name $Workload.Name -Status "unknown" -Message "Advanced Hunting no estuvo disponible; no se calculo telemetria."
            }
        }
    }
}

if ($HasAdvHunting -and $KQLAvailable) {

    # --- MDE ---
    if ($HasMDE) {
        Write-Step "Consultando MDE - Dispositivos onboarded..."
        try {
            Reset-GraphFailures
            # Dispositivos onboarded unicos en la ventana configurada
            $MdeDevices = Invoke-KQL -Label "MDE.Devices" -Query @"
DeviceInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where OnboardingStatus == "Onboarded"
| summarize LastSeen = max(Timestamp), OSPlatform = take_any(OSPlatform) by DeviceId
| summarize
    TotalDevices = dcount(DeviceId),
    Windows = dcountif(DeviceId, OSPlatform has "Windows"),
    MacOS = dcountif(DeviceId, OSPlatform has "macOS"),
    Linux = dcountif(DeviceId, OSPlatform has "Linux"),
    iOS = dcountif(DeviceId, OSPlatform has "iOS"),
    Android = dcountif(DeviceId, OSPlatform has "Android")
"@

            # Usuarios unicos con dispositivo MDE
            $MdeUsers = Invoke-KQL -Label "MDE.Users" -Query @"
DeviceInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where OnboardingStatus == "Onboarded"
| mv-expand LoggedOnUsers
| extend UserSid = tostring(LoggedOnUsers.Sid)
| where isnotempty(UserSid)
| summarize UniqueUsers = dcount(UserSid)
"@

            # Dispositivos sin senal 7+ dias
            $MdeStale = Invoke-KQL -Label "MDE.Stale" -Query @"
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize LastSeen = max(Timestamp) by DeviceId
| where LastSeen < ago(7d)
| summarize StaleDevices = count()
"@

            # Alertas MDE en la ventana configurada
            $MdeAlerts = Invoke-KQL -Label "MDE.Alerts" -Query @"
AlertInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where ServiceSource == "Microsoft Defender for Endpoint"
| summarize
    Total = count(),
    High = countif(Severity == "High"),
    Medium = countif(Severity == "Medium"),
    Low = countif(Severity == "Low"),
    Informational = countif(Severity == "Informational")
"@

            $DeviceCount = Get-KqlCount -Rows $MdeDevices -Name 'TotalDevices'
            $UserCount   = Get-KqlCount -Rows $MdeUsers -Name 'UniqueUsers'
            $StaleCount  = Get-KqlCount -Rows $MdeStale -Name 'StaleDevices'
            $AvgDevices  = if ($null -ne $DeviceCount -and $null -ne $UserCount -and $UserCount -gt 0) { [math]::Round($DeviceCount / $UserCount, 1) } else { $null }

            $Result.MDE = @{
                TelemetryStatus       = "collected"
                DevicesOnboarded     = $DeviceCount
                UniqueUsersObserved  = $UserCount
                AvgDevicesPerUser    = $AvgDevices
                DevicesStale7d       = $StaleCount
                TelemetryWindowDays  = $HuntingLookbackDays
                CoverageStatus       = "notCalculated"
                CoverageLimitation   = "Graph agregado no entrega un denominador unico de usuarios con entitlement MDE."
                Platforms            = @{
                    Windows = (Get-KqlCount -Rows $MdeDevices -Name 'Windows')
                    MacOS   = (Get-KqlCount -Rows $MdeDevices -Name 'MacOS')
                    Linux   = (Get-KqlCount -Rows $MdeDevices -Name 'Linux')
                    iOS     = (Get-KqlCount -Rows $MdeDevices -Name 'iOS')
                    Android = (Get-KqlCount -Rows $MdeDevices -Name 'Android')
                }
                AlertsWindow         = @{
                    Total         = (Get-KqlCount -Rows $MdeAlerts -Name 'Total')
                    High          = (Get-KqlCount -Rows $MdeAlerts -Name 'High')
                    Medium        = (Get-KqlCount -Rows $MdeAlerts -Name 'Medium')
                    Low           = (Get-KqlCount -Rows $MdeAlerts -Name 'Low')
                    Informational = (Get-KqlCount -Rows $MdeAlerts -Name 'Informational')
                }
            }
            Write-OK "MDE: $DeviceCount dispositivos onboarded, $UserCount usuarios observados, $StaleCount stale"
            Write-OK "MDE Alertas ${HuntingWindowLabel}: $(if($MdeAlerts -and $MdeAlerts[0]){$MdeAlerts[0].Total}else{0})"
            $ModulesExecuted.Add("MDE")
            $MdeFailures = @(Get-GraphFailures)
            if ($MdeFailures.Count -gt 0) { $Result.MDE.TelemetryStatus = "partial" }
            Set-ModuleStatus -Name "MDE" -Status $(if ($MdeFailures.Count -gt 0) { "warning" } else { "success" }) `
                -Message $(if ($MdeFailures.Count -gt 0) { "MDE devolvio datos parciales." } else { "MDE leido correctamente." }) `
                -Details @{ devicesOnboarded = $DeviceCount; telemetryWindowDays = $HuntingLookbackDays; graphFailures = $MdeFailures }
        } catch {
            Set-ModuleStatus -Name "MDE" -Status "error" -Message "No se pudo evaluar MDE." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
            Write-Warn "Error consultando MDE: $_"
        }
    } else {
        Set-ModuleStatus -Name "MDE" -Status "notApplicable" -Message "MDE no detectado en licenciamiento."
        Write-Skip "MDE no detectado - saltando"
    }

    # --- MDO ---
    if ($HasMDO) {
        Write-Step "Consultando MDO - Proteccion de correo..."
        try {
            Reset-GraphFailures
            $MdoStats = Invoke-KQL -Label "MDO.EmailEvents" -Query @"
EmailEvents
| where Timestamp > ago(${HuntingLookbackDays}d)
| summarize
    TotalEmails = count(),
    Phishing = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    DeliveredToInbox = countif(DeliveryAction == "Delivered"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Junked = countif(DeliveryAction == "Junked")
"@

            $MdoSafeLinks = Invoke-KQL -Label "MDO.SafeLinks" -Query @"
UrlClickEvents
| where Timestamp > ago(${HuntingLookbackDays}d)
| summarize
    TotalClicks = count(),
    Blocked = countif(ActionType == "ClickBlocked"),
    Allowed = countif(ActionType == "ClickAllowed"),
    PendingDetonation = countif(ActionType == "UrlClickPendingDetonation")
"@

            $MdoAlerts = Invoke-KQL -Label "MDO.Alerts" -Query @"
AlertInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where ServiceSource == "Microsoft Defender for Office 365"
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            $Result.MDO = @{
                TelemetryStatus      = "collected"
                EmailsProcessedWindow = (Get-KqlCount -Rows $MdoStats -Name 'TotalEmails')
                PhishingDetected   = (Get-KqlCount -Rows $MdoStats -Name 'Phishing')
                MalwareDetected    = (Get-KqlCount -Rows $MdoStats -Name 'Malware')
                SpamDetected       = (Get-KqlCount -Rows $MdoStats -Name 'Spam')
                Blocked            = (Get-KqlCount -Rows $MdoStats -Name 'Blocked')
                SafeLinks          = @{
                    TotalClicks = (Get-KqlCount -Rows $MdoSafeLinks -Name 'TotalClicks')
                    Blocked     = (Get-KqlCount -Rows $MdoSafeLinks -Name 'Blocked')
                    Allowed     = (Get-KqlCount -Rows $MdoSafeLinks -Name 'Allowed')
                }
                AlertsWindow       = @{
                    Total  = (Get-KqlCount -Rows $MdoAlerts -Name 'Total')
                    High   = (Get-KqlCount -Rows $MdoAlerts -Name 'High')
                    Medium = (Get-KqlCount -Rows $MdoAlerts -Name 'Medium')
                }
                TelemetryWindowDays = $HuntingLookbackDays
            }
            Write-OK "MDO: $(if($MdoStats -and $MdoStats[0]){$MdoStats[0].TotalEmails}else{0}) emails procesados en $HuntingWindowLabel, $(if($MdoStats -and $MdoStats[0]){$MdoStats[0].Phishing}else{0}) phishing detectado"
            Write-OK "Safe Links: $(if($MdoSafeLinks -and $MdoSafeLinks[0]){$MdoSafeLinks[0].Blocked}else{0}) clicks bloqueados"
            $ModulesExecuted.Add("MDO")
            $MdoFailures = @(Get-GraphFailures)
            if ($MdoFailures.Count -gt 0) { $Result.MDO.TelemetryStatus = "partial" }
            Set-ModuleStatus -Name "MDO" -Status $(if ($MdoFailures.Count -gt 0) { "warning" } else { "success" }) `
                -Message $(if ($MdoFailures.Count -gt 0) { "MDO devolvio datos parciales." } else { "MDO leido correctamente." }) `
                -Details @{ telemetryWindowDays = $HuntingLookbackDays; graphFailures = $MdoFailures }
        } catch {
            Set-ModuleStatus -Name "MDO" -Status "error" -Message "No se pudo evaluar MDO." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
            Write-Warn "Error consultando MDO: $_"
        }
    } else {
        Set-ModuleStatus -Name "MDO" -Status "notApplicable" -Message "MDO no detectado en licenciamiento."
        Write-Skip "MDO no detectado - saltando"
    }

    # --- MDA ---
    if ($HasMDA) {
        Write-Step "Consultando MDA - Cloud App Security..."
        try {
            Reset-GraphFailures
            $MdaStats = Invoke-KQL -Label "MDA.Events" -Query @"
CloudAppEvents
| where Timestamp > ago(${HuntingLookbackDays}d)
| summarize
    TotalEvents = count(),
    UniqueApps = dcount(Application),
    UniqueUsers = dcount(AccountObjectId)
"@

            $MdaAlerts = Invoke-KQL -Label "MDA.Alerts" -Query @"
AlertInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where ServiceSource in ("Microsoft Defender for Cloud Apps", "Microsoft Cloud App Security")
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            $Result.MDA = @{
                TelemetryStatus = "collected"
                EventsWindow   = (Get-KqlCount -Rows $MdaStats -Name 'TotalEvents')
                UniqueApps     = (Get-KqlCount -Rows $MdaStats -Name 'UniqueApps')
                UniqueUsers    = (Get-KqlCount -Rows $MdaStats -Name 'UniqueUsers')
                AlertsWindow   = @{
                    Total  = (Get-KqlCount -Rows $MdaAlerts -Name 'Total')
                    High   = (Get-KqlCount -Rows $MdaAlerts -Name 'High')
                    Medium = (Get-KqlCount -Rows $MdaAlerts -Name 'Medium')
                }
                TelemetryWindowDays = $HuntingLookbackDays
            }
            Write-OK "MDA: $($Result.MDA.UniqueApps) apps observadas, $($Result.MDA.EventsWindow) eventos en $HuntingWindowLabel"
            $ModulesExecuted.Add("MDA")
            $MdaFailures = @(Get-GraphFailures)
            if ($MdaFailures.Count -gt 0) { $Result.MDA.TelemetryStatus = "partial" }
            Set-ModuleStatus -Name "MDA" -Status $(if ($MdaFailures.Count -gt 0) { "warning" } else { "success" }) `
                -Message $(if ($MdaFailures.Count -gt 0) { "MDA devolvio datos parciales." } else { "MDA leido correctamente." }) `
                -Details @{ telemetryWindowDays = $HuntingLookbackDays; graphFailures = $MdaFailures }
        } catch {
            Set-ModuleStatus -Name "MDA" -Status "error" -Message "No se pudo evaluar MDA." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
            Write-Warn "Error consultando MDA: $_"
        }
    } else {
        Set-ModuleStatus -Name "MDA" -Status "notApplicable" -Message "MDA no detectado en licenciamiento."
        Write-Skip "MDA no detectado - saltando"
    }

    # --- MDI ---
    if ($HasMDI) {
        Write-Step "Consultando MDI - Defender for Identity..."
        try {
            Reset-GraphFailures
            # Solo conteo de DCs; nunca retorna nombres/FQDN.
            $MdiDCs = Invoke-KQL -Label "MDI.DomainControllers" -Query @"
IdentityLogonEvents
| where Timestamp > ago(${HuntingLookbackDays}d)
| summarize DCsMonitored = dcount(DeviceName)
"@

            # Volumen de eventos
            $MdiStats = Invoke-KQL -Label "MDI.Logons" -Query @"
IdentityLogonEvents
| where Timestamp > ago(${HuntingLookbackDays}d)
| summarize
    TotalEvents = count(),
    UniqueUsers = dcount(AccountUpn),
    SuccessLogons = countif(ActionType == "LogonSuccess"),
    FailedLogons = countif(ActionType == "LogonFailed")
"@

            # Alertas MDI
            $MdiAlerts = Invoke-KQL -Label "MDI.Alerts" -Query @"
AlertInfo
| where Timestamp > ago(${HuntingLookbackDays}d)
| where ServiceSource == "Microsoft Defender for Identity"
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            $DCCount = Get-KqlCount -Rows $MdiDCs -Name 'DCsMonitored'

            $Result.MDI = @{
                TelemetryStatus   = "collected"
                DCsMonitored     = $DCCount
                LogonEventsWindow = (Get-KqlCount -Rows $MdiStats -Name 'TotalEvents')
                UniqueUsers      = (Get-KqlCount -Rows $MdiStats -Name 'UniqueUsers')
                SuccessLogons    = (Get-KqlCount -Rows $MdiStats -Name 'SuccessLogons')
                FailedLogons     = (Get-KqlCount -Rows $MdiStats -Name 'FailedLogons')
                AlertsWindow     = @{
                    Total  = (Get-KqlCount -Rows $MdiAlerts -Name 'Total')
                    High   = (Get-KqlCount -Rows $MdiAlerts -Name 'High')
                    Medium = (Get-KqlCount -Rows $MdiAlerts -Name 'Medium')
                }
                TelemetryWindowDays = $HuntingLookbackDays
                Note             = "Validar con el cliente el total de DCs del dominio para confirmar cobertura completa"
            }
            Write-OK "MDI: $DCCount DCs monitoreados, $(if($MdiStats -and $MdiStats[0]){$MdiStats[0].TotalEvents}else{0}) logon events en $HuntingWindowLabel"
            Write-OK "MDI: $(if($MdiStats -and $MdiStats[0]){$MdiStats[0].FailedLogons}else{0}) logons fallidos detectados"
            $ModulesExecuted.Add("MDI")
            $MdiFailures = @(Get-GraphFailures)
            if ($MdiFailures.Count -gt 0) { $Result.MDI.TelemetryStatus = "partial" }
            Set-ModuleStatus -Name "MDI" -Status $(if ($MdiFailures.Count -gt 0) { "warning" } else { "success" }) `
                -Message $(if ($MdiFailures.Count -gt 0) { "MDI devolvio datos parciales." } else { "MDI leido correctamente." }) `
                -Details @{ dcsMonitored = $DCCount; telemetryWindowDays = $HuntingLookbackDays; graphFailures = $MdiFailures }
        } catch {
            Set-ModuleStatus -Name "MDI" -Status "error" -Message "No se pudo evaluar MDI." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
            Write-Warn "Error consultando MDI: $_"
        }
    } else {
        Set-ModuleStatus -Name "MDI" -Status "notApplicable" -Message "MDI no detectado en licenciamiento."
        Write-Skip "MDI no detectado - saltando"
    }
} elseif (-not $HasAdvHunting) {
    Write-Skip "No se detectaron licencias de seguridad E5 - saltando Advanced Hunting"
}

# ============================================================================
# FASE 4b: SECURE SCORE CONTROLS (para todos los productos Defender)
# ============================================================================
Write-Section "Fase 4b: Controles de Secure Score por producto"

# Map service names in Secure Score to our product keys
$ServiceMap = @{
    "MDO"       = @{ Key = "MDO";     Has = $HasMDO;     Label = "Defender for Office 365" }
    "MCAS"      = @{ Key = "MDA";     Has = $HasMDA;     Label = "Defender for Cloud Apps" }
    "MDATP"     = @{ Key = "MDE";     Has = $HasMDE;     Label = "Defender for Endpoint" }
    "Azure ATP" = @{ Key = "MDI";     Has = $HasMDI;     Label = "Defender for Identity" }
    "MIP"       = @{ Key = "Purview"; Has = $HasPurview; Label = "Microsoft Purview" }
}
if (-not $HasPurview) { Set-ModuleStatus -Name "Purview" -Status "notApplicable" -Message "Purview no detectado en licenciamiento." }

try {
    $ScoreData = $null
    $LatestScoreFile = if ($SecureScoreJsonPath) {
        if (Test-Path -LiteralPath $SecureScoreJsonPath) { Get-Item -LiteralPath $SecureScoreJsonPath }
        else { $null }
    } elseif ($LicData.PSObject.Properties['RunId'] -and $LicData.RunId) {
        Get-Item -LiteralPath (Join-Path $OutputPath "$($LicData.RunId)_secure_score.json") -ErrorAction SilentlyContinue
    } else {
        Get-ChildItem -Path $OutputPath -Filter "*_secure_score.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($LatestScoreFile) {
        $ScoreData = Get-Content $LatestScoreFile.FullName -Raw | ConvertFrom-Json
        if ($LicData.PSObject.Properties['SchemaVersion'] -and [string]$LicData.SchemaVersion -eq '4.0') {
            if (-not $ScoreData.PSObject.Properties['SchemaVersion'] -or [string]$ScoreData.SchemaVersion -ne '4.0' -or
                -not $ScoreData.PSObject.Properties['RunId'] -or -not $ScoreData.RunId) {
                throw "Secure Score no cumple el contrato v4 de esta corrida."
            }
        }
        if ($LicData.PSObject.Properties['RunId'] -and $LicData.RunId -and
            $ScoreData.PSObject.Properties['RunId'] -and $ScoreData.RunId -and
            [string]$LicData.RunId -ne [string]$ScoreData.RunId) {
            throw "Secure Score pertenece a otra corrida."
        }
        if ($LicData.PSObject.Properties['TenantFingerprint'] -and $LicData.TenantFingerprint -and
            $ScoreData.PSObject.Properties['TenantFingerprint'] -and $ScoreData.TenantFingerprint -and
            [string]$LicData.TenantFingerprint -ne [string]$ScoreData.TenantFingerprint) {
            throw "Secure Score pertenece a otro tenant."
        }
    }

    if ($ScoreData -and $ScoreData.AllRecommendations) {
        foreach ($SvcName in $ServiceMap.Keys) {
            $Map = $ServiceMap[$SvcName]
            if (-not $Map.Has) { continue }

            $ProductKey = $Map.Key
            Write-Step "Analizando controles de Secure Score para $($Map.Label)..."

            # Initialize product section if KQL didn't populate it
            if (-not $Result.ContainsKey($ProductKey)) {
                if ($ProductKey -eq "MDO") {
                    $Result.MDO = @{
                        TelemetryStatus = "unavailable"
                        Note = "Telemetria KQL no disponible; solo se evaluan controles de configuracion."
                    }
                } elseif ($ProductKey -eq "MDA") {
                    $Result.MDA = @{
                        TelemetryStatus = "unavailable"
                        Note = "Telemetria KQL no disponible; solo se evaluan controles de configuracion."
                    }
                } elseif ($ProductKey -eq "MDE") {
                    $Result.MDE = @{
                        TelemetryStatus = "unavailable"
                        CoverageStatus = "notCalculated"
                        Note = "Telemetria KQL no disponible; solo se evaluan controles de configuracion."
                    }
                } elseif ($ProductKey -eq "MDI") {
                    $Result.MDI = @{
                        TelemetryStatus = "unavailable"
                        Note = "Telemetria KQL no disponible; solo se evaluan controles de configuracion."
                    }
                } elseif ($ProductKey -eq "Purview") {
                    $Result.Purview = @{
                        Note = "Configuracion evaluada via Secure Score."
                    }
                }
                Write-OK "$ProductKey inicializado (sin datos KQL)"
                if (-not ($ModulesExecuted -contains $ProductKey)) { $ModulesExecuted.Add($ProductKey) }
            }

            # Extract controls for this service
            $Controls = @($ScoreData.AllRecommendations | Where-Object { $_.Service -eq $SvcName })
            $Enabled  = @($Controls | Where-Object { $_.ImplementationStatus -eq 'Implemented' }).Count
            $Partial  = @($Controls | Where-Object { $_.ImplementationStatus -eq 'Partial' }).Count
            $NotImpl  = @($Controls | Where-Object { $_.ImplementationStatus -eq 'NotImplemented' }).Count
            $UnknownControls = @($Controls | Where-Object { $_.ImplementationStatus -eq 'Unknown' }).Count

            $Result[$ProductKey].SecureScoreControls = @{
                Total          = $Controls.Count
                FullyEnabled   = $Enabled
                Partial        = $Partial
                NotImplemented = $NotImpl
                Unknown        = $UnknownControls
                Details        = @($Controls | ForEach-Object {
                    $Pct = if ($null -ne $_.MaxScore -and $_.MaxScore -gt 0) { [math]::Round($_.CurrentScore / $_.MaxScore * 100) } else { $null }
                    [PSCustomObject]@{
                        Title                = $_.Title
                        ScoreInPercentage    = $Pct
                        ImplementationStatus = $_.ImplementationStatus
                        Improvement          = $_.Improvement
                        Category             = $_.Category
                        Service              = $SvcName
                        DataQuality          = if ($_.PSObject.Properties['DataQuality']) { $_.DataQuality } else { 'legacy' }
                    }
                } | Sort-Object ScoreInPercentage -Descending)
            }
            Write-OK "$ProductKey Secure Score: $Enabled/$($Controls.Count) controles completados, $Partial parciales, $NotImpl pendientes"
            if ($ProductKey -eq 'Purview') {
                Set-ModuleStatus -Name "Purview" -Status $(if ($UnknownControls -gt 0) { "warning" } else { "success" }) `
                    -Message $(if ($UnknownControls -gt 0) { "Purview evaluado con controles de Secure Score parcialmente validos." } else { "Purview evaluado mediante controles de Secure Score." })
            }
        }
    } else {
        Write-Warn "No se encontro archivo de Secure Score en $OutputPath"
        if ($HasPurview) { Set-ModuleStatus -Name "Purview" -Status "unknown" -Message "No hubo evidencia de Secure Score para Purview." }
    }
} catch {
    if ($HasPurview) { Set-ModuleStatus -Name "Purview" -Status "error" -Message "No se pudo correlacionar evidencia de Purview con Secure Score." }
    Write-Warn "Error analizando Secure Score: $_"
}

# ============================================================================
# FASE 5: INTUNE
# ============================================================================
if ($HasIntune) {
    Write-Section "Fase 5: Microsoft Intune"

    Write-Step "Obteniendo estadisticas de Intune (APIs de conteo)..."
    try {
        Reset-GraphFailures
        # Paginacion exacta con propiedades no identificadoras. No se extrapola una
        # primera pagina ni se solicitan nombres, seriales, usuarios o IDs.
        $DevicesSample = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=complianceState,operatingSystem,lastSyncDateTime&`$top=999" -Label "Intune devices")
        $TotalDevices = $DevicesSample.Count

        if ($TotalDevices -gt 0) {
            $Compliant = 0; $NonCompliant = 0; $StaleDevices = 0
            $Platforms = @{}
            $StaleDate = (Get-Date).AddDays(-$DeviceStaleDays)

            if ($DevicesSample) {
                foreach ($D in $DevicesSample) {
                    if ($D.complianceState -eq "compliant") { $Compliant++ }
                    elseif ($D.complianceState -eq "noncompliant") { $NonCompliant++ }
                    $OS = if ($D.operatingSystem) { $D.operatingSystem } else { "Unknown" }
                    if (-not $Platforms.ContainsKey($OS)) { $Platforms[$OS] = 0 }
                    $Platforms[$OS]++
                    if ($D.lastSyncDateTime -and ([datetime]$D.lastSyncDateTime -lt $StaleDate)) { $StaleDevices++ }
                }
            }
            $Unknown = [math]::Max(0, $TotalDevices - $Compliant - $NonCompliant)
            $CompliancePct = if ($TotalDevices -gt 0) { [math]::Round(($Compliant / $TotalDevices) * 100, 1) } else { 0 }

            $Result.Intune = @{
                TelemetryStatus  = "collected"
                DevicesEnrolled  = $TotalDevices
                Compliant        = $Compliant
                NonCompliant     = $NonCompliant
                Unknown          = $Unknown
                CompliancePct    = $CompliancePct
                StaleDevices     = $StaleDevices
                StaleThresholdDays = $DeviceStaleDays
                Platforms        = $Platforms
                Ownership        = @{ Corporate = 0; Personal = 0 }
            }

            $CompColor = if ($CompliancePct -ge 80) { "Green" } elseif ($CompliancePct -ge 50) { "Yellow" } else { "Red" }
            Write-Host "  [OK] Intune: $TotalDevices dispositivos enrolled ($CompliancePct% compliant)" -ForegroundColor $CompColor
            Write-OK "Plataformas: $(($Platforms.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ', ')"
            Write-OK "Stale ${DeviceStaleDays}d+: $StaleDevices dispositivos"
            $ModulesExecuted.Add("Intune")
            $IntuneFailures = @(Get-GraphFailures)
            Set-ModuleStatus -Name "Intune" -Status $(if ($IntuneFailures.Count -gt 0) { "warning" } else { "success" }) `
                -Message $(if ($IntuneFailures.Count -gt 0) { "Intune devolvio datos parciales." } else { "Intune leido correctamente." }) `
                -Details @{ devices = $TotalDevices; staleThresholdDays = $DeviceStaleDays; graphFailures = $IntuneFailures }
        } else {
            $IntuneFailures = @(Get-GraphFailures)
            $IntuneStatus = if ($IntuneFailures.Count -gt 0) { "unknown" } else { "success" }
            $IntuneMessage = if ($IntuneFailures.Count -gt 0) { "Graph no permitio confirmar el inventario de Intune." } else { "Graph confirmo que no hay dispositivos administrados en Intune." }
            $Result.Intune = @{
                TelemetryStatus   = if ($IntuneFailures.Count -gt 0) { "unavailable" } else { "collected" }
                DevicesEnrolled   = if ($IntuneFailures.Count -gt 0) { $null } else { 0 }
                Compliant         = if ($IntuneFailures.Count -gt 0) { $null } else { 0 }
                NonCompliant      = if ($IntuneFailures.Count -gt 0) { $null } else { 0 }
                Unknown           = if ($IntuneFailures.Count -gt 0) { $null } else { 0 }
                CompliancePct     = $null
                StaleDevices      = if ($IntuneFailures.Count -gt 0) { $null } else { 0 }
                StaleThresholdDays = $DeviceStaleDays
                Platforms         = @{}
            }
            Set-ModuleStatus -Name "Intune" -Status $IntuneStatus -Message $IntuneMessage -Details @{ graphFailures = $IntuneFailures }
            Write-Warn $IntuneMessage
        }
    } catch {
        Set-ModuleStatus -Name "Intune" -Status "error" -Message "No se pudo evaluar Intune." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
        Write-Warn "Error consultando Intune: $_"
    }
} else {
    Set-ModuleStatus -Name "Intune" -Status "notApplicable" -Message "Intune no detectado en licenciamiento."
    Write-Skip "Intune no detectado - saltando"
}

# ============================================================================
# FASE 6: COPILOT
# ============================================================================
if ($HasCopilot) {
    Write-Section "Fase 6: Microsoft 365 Copilot"

    Write-Step "Obteniendo uso de Copilot (ultimos 30 dias)..."
    try {
        Reset-GraphFailures
        $CopilotReport = Invoke-GraphSafe -Uri "https://graph.microsoft.com/beta/reports/getMicrosoft365CopilotUserCountSummary(period='D30')?`$format=application/json"

        if ($CopilotReport -and $CopilotReport.value) {
            $Summary = @($CopilotReport.value[0].adoptionByProduct | Where-Object { [int]$_.reportPeriod -eq 30 } | Select-Object -First 1)
            $CopilotEnabled = if ($Summary) { [int]$Summary.anyAppEnabledUsers } else { 0 }
            $ActiveCopilot  = if ($Summary) { [int]$Summary.anyAppActiveUsers } else { 0 }
            $CopilotPct = if ($CopilotEnabled -gt 0) { [math]::Round(($ActiveCopilot / $CopilotEnabled) * 100, 1) } else { 0 }

            $Result.Copilot = @{
                TelemetryStatus  = "collected"
                EnabledUsers30d  = $CopilotEnabled
                ActiveUsers30d   = $ActiveCopilot
                AdoptionPct      = $CopilotPct
                Source           = "getMicrosoft365CopilotUserCountSummary"
                ApiVersion       = "beta"
            }
            Write-OK "Copilot: $ActiveCopilot/$CopilotEnabled usuarios activos ($CopilotPct%)"
            Set-ModuleStatus -Name "Copilot" -Status "success" -Message "Copilot leido mediante reporte agregado." -Details @{ enabledUsers = $CopilotEnabled; activeUsers = $ActiveCopilot; apiVersion = "beta" }
        } else {
            Set-ModuleStatus -Name "Copilot" -Status "unknown" -Message "Graph no devolvio el resumen agregado de Copilot." -Details @{ graphFailures = @(Get-GraphFailures) }
            Write-Warn "No se obtuvieron datos de uso de Copilot"
        }
        $ModulesExecuted.Add("Copilot")
    } catch {
        Set-ModuleStatus -Name "Copilot" -Status "error" -Message "No se pudo evaluar Copilot." -Details @{ error = [string]$_; graphFailures = @(Get-GraphFailures) }
        Write-Warn "Error consultando Copilot: $_"
    }
} else {
    Set-ModuleStatus -Name "Copilot" -Status "notApplicable" -Message "Copilot no detectado en licenciamiento."
    Write-Skip "Copilot no detectado - saltando"
}

# ============================================================================
# FASE 7: EXPORTAR JSON
# ============================================================================
Write-Section "Fase 7: Exportando resultados"

$Result.ModulesExecuted = @($ModulesExecuted)
$Result.ModuleStatus = $ModuleStatus

$OutputPrefix = if ($RunId) { $RunId } else { Get-Date -Format "yyyyMMdd_HHmm" }
$JsonPath  = Join-Path $OutputPath "${OutputPrefix}_security_adoption.json"
$Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
if (-not $OnWindowsHost) { & /bin/chmod 600 $JsonPath }
Write-OK "JSON: $JsonPath"

# ============================================================================
# RESUMEN FINAL
# ============================================================================
$Duration = (Get-Date) - $ScriptStart

Write-Section "COMPLETADO en $([math]::Round($Duration.TotalSeconds)) segundos"
Write-Host "  Tenant fingerprint:  $($Result.TenantFingerprint)" -ForegroundColor Green
Write-Host "  Modulos ejecutados:  $($ModulesExecuted.Count) de 8" -ForegroundColor Green
Write-Host "  Modulos: $($ModulesExecuted -join ', ')" -ForegroundColor Gray
Write-Host "`n  Resultados en: $JsonPath" -ForegroundColor Cyan

# Resumen rapido de hallazgos
Write-Host "`n  Hallazgos clave:" -ForegroundColor White
if ($Result.ContainsKey('Entra') -and $Result.Entra) {
    if ($Result.Entra.ContainsKey('MFA') -and $Result.Entra.MFA) {
        $MfaColor = if ($Result.Entra.MFA.PctCapable -ge 90) { "Green" } elseif ($Result.Entra.MFA.PctCapable -ge 70) { "Yellow" } else { "Red" }
        Write-Host "    MFA capable:          $($Result.Entra.MFA.PctCapable)%" -ForegroundColor $MfaColor
    }
    if ($Result.Entra.ContainsKey('ConditionalAccess') -and $Result.Entra.ConditionalAccess) {
        Write-Host "    CA Policies activas:  $($Result.Entra.ConditionalAccess.Enabled)" -ForegroundColor $(if($Result.Entra.ConditionalAccess.Enabled -gt 0){"Green"}else{"Red"})
    }
    if ($Result.Entra.ContainsKey('RiskyUsers') -and $Result.Entra.RiskyUsers) {
        $RColor = if ($Result.Entra.RiskyUsers.High -gt 0) { "Red" } elseif ($Result.Entra.RiskyUsers.TotalAtRisk -gt 0) { "Yellow" } else { "Green" }
        Write-Host "    Usuarios riesgosos:   $($Result.Entra.RiskyUsers.TotalAtRisk) (High:$($Result.Entra.RiskyUsers.High))" -ForegroundColor $RColor
    }
}
if ($Result.ContainsKey('MDE') -and $Result.MDE) {
    Write-Host "    MDE dispositivos:     $($Result.MDE.DevicesOnboarded); usuarios observados: $($Result.MDE.UniqueUsersObserved)" -ForegroundColor Green
}
if ($Result.ContainsKey('MDO') -and $Result.MDO) {
    Write-Host "    MDO Emails ${HuntingWindowLabel}:   $($Result.MDO.EmailsProcessedWindow) (Phishing:$($Result.MDO.PhishingDetected))" -ForegroundColor Green
}
if ($Result.ContainsKey('MDA') -and $Result.MDA) {
    Write-Host "    MDA Apps monitoreadas:$($Result.MDA.UniqueApps)" -ForegroundColor $(if($Result.MDA.UniqueApps -gt 0){"Green"}else{"Yellow"})
}
if ($Result.ContainsKey('MDI') -and $Result.MDI) {
    Write-Host "    MDI DCs monitoreados: $($Result.MDI.DCsMonitored)" -ForegroundColor $(if($Result.MDI.DCsMonitored -gt 0){"Green"}else{"Red"})
}
if ($Result.ContainsKey('Intune') -and $Result.Intune) {
    if ($null -ne $Result.Intune.CompliancePct) {
        $IntColor = if ($Result.Intune.CompliancePct -ge 80) { "Green" } elseif ($Result.Intune.CompliancePct -ge 50) { "Yellow" } else { "Red" }
        Write-Host "    Intune Compliance:    $($Result.Intune.CompliancePct)% ($($Result.Intune.Compliant)/$($Result.Intune.DevicesEnrolled))" -ForegroundColor $IntColor
    } else {
        Write-Host "    Intune Compliance:    N/D ($($Result.Intune.DevicesEnrolled) dispositivos)" -ForegroundColor Gray
    }
}
if ($Result.ContainsKey('Copilot') -and $Result.Copilot) {
    Write-Host "    Copilot Adopcion:     $($Result.Copilot.AdoptionPct)% ($($Result.Copilot.ActiveUsers30d)/$($Result.Copilot.EnabledUsers30d))" -ForegroundColor $(if($Result.Copilot.AdoptionPct -ge 50){"Green"}else{"Yellow"})
}

Write-Host ""
if ($ManagedSession -and -not $PreserveGraphSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion cerrada`n"
} else {
    Write-OK "Sesion Graph mantenida`n"
}
