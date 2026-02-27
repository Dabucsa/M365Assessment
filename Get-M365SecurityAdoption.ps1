# Modulos requeridos: Microsoft.Graph.Authentication
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Security Adoption Assessment v1
.DESCRIPTION
    Complemento de Get-MSLicensingReport.ps1. Mide el USO REAL de los productos
    de seguridad del tenant consultando:
    - Entra ID P1: Conditional Access, MFA, SSPR
    - Entra ID P2: Risky Users, PIM, Access Reviews
    - MDE: Dispositivos onboarded, cobertura por usuario (via KQL)
    - MDO: Correos procesados, phishing bloqueado (via KQL)
    - MDA: Apps cloud monitoreadas (via KQL)
    - MDI: Domain Controllers monitoreados (via KQL)
    - Intune: Dispositivos enrolled, compliance
    - Copilot: Uso real vs licencias

    Detecta automaticamente que licencias tiene el tenant y ejecuta
    solo los modulos correspondientes.
.PARAMETER OutputPath
    Carpeta con los archivos generados por Get-MSLicensingReport (default: .\output)
.PARAMETER InactiveDays
    Dias sin check-in para considerar dispositivo inactivo (default: 30)
.EXAMPLE
    .\Get-MSSecurityAdoption.ps1
    .\Get-MSSecurityAdoption.ps1 -OutputPath ".\output"
.NOTES
    Requiere: Global Reader (minimo)
    Modulos:  Microsoft.Graph.Authentication
              (tambien se cargan: Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users via Script 1)
    Permisos adicionales segun modulos:
      - Policy.Read.All (CA)
      - UserAuthenticationMethod.Read.All (MFA/SSPR)
      - Reports.Read.All (Copilot usage)
      - DeviceManagementManagedDevices.Read.All (Intune)
      - RoleManagement.Read.All (PIM)
      - IdentityRiskyUser.Read.All (Risky Users)
      - ThreatHunting.Read.All (Advanced Hunting - MDE/MDO/MDA/MDI)
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
              Las queries KQL de Advanced Hunting son consultas de lectura sobre telemetria existente.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\output",
    [int]$InactiveDays = 30
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

function Write-Skip {
    param([string]$Message)
    Write-Host "  [--] $Message" -ForegroundColor DarkGray
}

function Invoke-GraphSafe {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [object]$Body,
        [int]$MaxRetries = 3
    )
    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        try {
            $Params = @{ Method = $Method; Uri = $Uri; ErrorAction = "Stop"; OutputType = "Hashtable" }
            if ($Body) { $Params.Body = $Body; $Params.ContentType = "application/json" }
            return Invoke-MgGraphRequest @Params
        } catch {
            $ErrMsg = $_.Exception.Message
            if ($ErrMsg -match "401|403|Forbidden|Unauthorized|Authorization|Insufficient") {
                Write-Warn "Sin permisos para: $Uri"
                return $null
            }
            if ($ErrMsg -match "404|NotFound") {
                Write-Warn "No disponible: $Uri"
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
    param([string]$Query)
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
        if ($ErrMsg -match "429|Throttl") {
            Write-Warn "Throttled - saltando query"
        } elseif ($ErrMsg -match "401|403|Forbidden|Unauthorized") {
            Write-Warn "Sin permisos para Advanced Hunting"
        } else {
            Write-Warn "KQL fallo: $($ErrMsg.Substring(0, [math]::Min(80, $ErrMsg.Length)))"
        }
        return @()
    }
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

# ============================================================================
# INICIO
# ============================================================================
$ScriptStart = Get-Date

Write-Host ""
Write-Host "  Microsoft 365 Security Adoption Assessment" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host ""

# ============================================================================
# FASE 1: CONEXION + CARGA DE DATOS PREVIOS
# ============================================================================
Write-Section "Fase 1: Conexion y Deteccion de Capacidades"

# Cargar report_data.json del Script 1
$JsonFile = Get-ChildItem -Path $OutputPath -Filter "*_report_data.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $JsonFile) {
    Write-Warn "No se encontro report_data.json en '$OutputPath'. Ejecuta primero Get-MSLicensingReport.ps1"
    exit 1
}
Write-OK "Datos de licenciamiento: $($JsonFile.Name)"
$LicData = Get-Content $JsonFile.FullName -Raw | ConvertFrom-Json

# Cargar Users CSV para cruzar datos con usuarios licenciados
$UserCsvFile = Get-ChildItem -Path $OutputPath -Filter "*_02_Users.csv" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
$LicensedUPNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($UserCsvFile) {
    Write-OK "Users CSV: $($UserCsvFile.Name)"
    $LicensedUsers = Import-Csv $UserCsvFile.FullName
    foreach ($U in $LicensedUsers) {
        if ($U.UPN) { [void]$LicensedUPNs.Add($U.UPN.Trim()) }
    }
    Write-OK "Usuarios licenciados cargados: $($LicensedUPNs.Count)"
} else {
    Write-Warn "No se encontro Users CSV - los porcentajes de MFA se calcularan contra todo el directorio"
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
$HasPurview      = ($TenantCategories | Where-Object { $_ -like "Purview_*" }).Count -gt 0
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

# Conectar a Graph
$Scopes = @(
    "Policy.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Reports.Read.All",
    "RoleManagement.Read.All",
    "IdentityRiskyUser.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "ThreatHunting.Read.All"
)

Write-Step "Conectando a Microsoft Graph..."
$PreExistingSession = $false
try {
    try { $ExistingCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { $ExistingCtx = $null }
    if ($ExistingCtx -and $ExistingCtx.Account) {
        $PreExistingSession = $true
        $Context = $ExistingCtx
        Write-OK "Reusando sesion existente: $($Context.Account)"
    } else {
        $ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true }
        $TenantId = $LicData.TenantId
        if ($TenantId) { $ConnectParams.TenantId = $TenantId }
        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext
        Write-OK "Conectado como: $($Context.Account)"
    }
} catch {
    Write-Warn "No se pudo conectar: $_"
    exit 1
}

# Resultado
$ModulesExecuted = [System.Collections.Generic.List[string]]::new()
$Result = @{
    GeneratedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion    = "1.0"
    TenantId         = $LicData.TenantId
    TenantName       = $LicData.TenantName
    TenantDomain     = $LicData.TenantDomain
    TotalLicensedUsers = $LicData.TotalLicensedUsers
    ModulesExecuted  = $null  # se llena al final
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
        # Solo traer campos necesarios: nombre, estado y conditions.users para AllUsers detection
        $CaPolicies = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions"
        $CaEnabled    = @($CaPolicies | Where-Object { $_.state -eq "enabled" })
        $CaReportOnly = @($CaPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
        $CaDisabled   = @($CaPolicies | Where-Object { $_.state -eq "disabled" })

        $AllUsersPolicy = $false
        foreach ($Pol in $CaEnabled) {
            $IncUsers = $Pol.conditions.users.includeUsers
            if ($IncUsers -contains "All") { $AllUsersPolicy = $true; break }
        }

        # Cobertura de licenciados
        $LicCovered = if ($AllUsersPolicy) { $LicensedUPNs.Count } else { 0 }
        $LicCoveragePct = if ($LicensedUPNs.Count -gt 0) { [math]::Round(($LicCovered / $LicensedUPNs.Count) * 100, 1) } else { 0 }

        $EntraData.ConditionalAccess = @{
            Total             = $CaPolicies.Count
            Enabled           = $CaEnabled.Count
            ReportOnly        = $CaReportOnly.Count
            Disabled          = $CaDisabled.Count
            LicCovered        = $LicCovered
            LicTotal          = $LicensedUPNs.Count
            LicCoveragePct    = $LicCoveragePct
            HasAllUsersPolicy = $AllUsersPolicy
        }
        Write-OK "CA Policies: $($CaPolicies.Count) total ($($CaEnabled.Count) activas, $($CaReportOnly.Count) report-only, $($CaDisabled.Count) deshabilitadas)"
        Write-OK "CA AllUsers policy activa: $AllUsersPolicy"
        $ModulesExecuted.Add("ConditionalAccess")
    } catch {
        Write-Warn "No se pudo obtener CA policies: $_"
    }

    # --- MFA & SSPR Registration ---
    # Estrategia hibrida:
    #  - Si hay <=500 licenciados: consultar userRegistrationDetails filtrado por UPN (datos exactos)
    #  - Si hay >500 licenciados: usar APIs agregadas (ligero pero contra todo el directorio members)
    $LicCount = $LicensedUPNs.Count
    Write-Step "Obteniendo estado de registro de MFA y SSPR..."
    try {
        if ($LicCount -gt 0 -and $LicCount -le 500) {
            # --- MODO EXACTO: Consultar solo los usuarios licenciados ---
            $AllDetails = [System.Collections.Generic.List[object]]::new()
            $UPNArray = @($LicensedUPNs)
            $BatchSize = 50  # ~50 UPNs por llamada para no exceder limites de URL
            for ($i = 0; $i -lt $UPNArray.Count; $i += $BatchSize) {
                $Batch = $UPNArray[$i..([math]::Min($i + $BatchSize - 1, $UPNArray.Count - 1))]
                $FilterParts = $Batch | ForEach-Object { "userPrincipalName eq '$_'" }
                $Filter = $FilterParts -join " or "
                $Uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$filter=$Filter&`$select=userPrincipalName,isMfaRegistered,isMfaCapable,isSsprRegistered,isSsprEnabled,isSsprCapable,methodsRegistered"
                $Resp = Invoke-GraphSafe -Uri $Uri
                if ($Resp -and $Resp.value) { $AllDetails.AddRange($Resp.value) }
            }

            # IMPORTANTE: el endpoint puede ignorar el $filter y devolver todos los usuarios
            # del tenant. Cross-referenciamos contra LicensedUPNs para garantizar exactitud.
            if ($LicensedUPNs.Count -gt 0 -and $AllDetails.Count -gt $LicensedUPNs.Count) {
                Write-Warn "API retorno $($AllDetails.Count) registros pero solo hay $($LicensedUPNs.Count) licenciados — filtrando por UPN"
                $AllDetails = [System.Collections.Generic.List[object]]@(
                    $AllDetails | Where-Object { $LicensedUPNs.Contains($_.userPrincipalName) }
                )
            }

            # Calcular MFA y SSPR desde datos exactos de licenciados
            $MfaCapable = ($AllDetails | Where-Object { $_.isMfaCapable -eq $true }).Count
            $MfaRegistered = ($AllDetails | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $SsprRegistered = ($AllDetails | Where-Object { $_.isSsprRegistered -eq $true }).Count
            $SsprEnabled = ($AllDetails | Where-Object { $_.isSsprEnabled -eq $true }).Count
            $TotalLic = $AllDetails.Count
            if ($TotalLic -eq 0) { $TotalLic = $LicCount }

            $MfaPct  = if ($TotalLic -gt 0) { [math]::Round(($MfaCapable / $TotalLic) * 100, 1) } else { 0 }
            $SsprPct = if ($TotalLic -gt 0) { [math]::Round(($SsprRegistered / $TotalLic) * 100, 1) } else { 0 }

            $EntraData.MFA = @{
                Registered       = $MfaCapable
                NotRegistered    = $TotalLic - $MfaCapable
                TotalUsers       = $TotalLic
                PctRegistered    = $MfaPct
                MfaCapable       = $MfaCapable
                MfaRegistered    = $MfaRegistered
                LicRegistered    = $MfaCapable
                LicTotal         = $TotalLic
                LicPctRegistered = $MfaPct
            }
            $EntraData.SSPR = @{
                Registered       = $SsprRegistered
                NotRegistered    = $TotalLic - $SsprRegistered
                Enabled          = $SsprEnabled
                TotalUsers       = $TotalLic
                PctRegistered    = $SsprPct
                LicRegistered    = $SsprRegistered
                LicTotal         = $TotalLic
                LicPctRegistered = $SsprPct
            }
            Write-OK "MFA:  $MfaCapable/$TotalLic licenciados capable ($MfaPct%)"
            Write-OK "SSPR: $SsprRegistered/$TotalLic licenciados registrados ($SsprPct%)"

            # Metodos de autenticacion desde datos per-user
            $MethodCounts = @{ Authenticator = 0; PhoneAuth = 0; FIDO2 = 0; Email = 0; WHfB = 0; Passwordless = 0 }
            foreach ($D in $AllDetails) {
                if (-not $D.methodsRegistered) { continue }
                foreach ($Meth in $D.methodsRegistered) {
                    switch ($Meth) {
                        "microsoftAuthenticatorPush"         { $MethodCounts.Authenticator++ }
                        "mobilePhone"                        { $MethodCounts.PhoneAuth++ }
                        "fido2SecurityKey"                    { $MethodCounts.FIDO2++ }
                        "email"                              { $MethodCounts.Email++ }
                        "windowsHelloForBusiness"            { $MethodCounts.WHfB++ }
                        "microsoftAuthenticatorPasswordless" { $MethodCounts.Passwordless++ }
                        "passKeyDeviceBound"                 { $MethodCounts.Passwordless++ }
                    }
                }
            }
            $EntraData.AuthMethods = $MethodCounts
            $EntraData.AuthMethodsLicensed = $MethodCounts
            Write-OK "Metodos (licenciados): Auth=$($MethodCounts.Authenticator), Phone=$($MethodCounts.PhoneAuth), FIDO2=$($MethodCounts.FIDO2), WHfB=$($MethodCounts.WHfB)"

            $ModulesExecuted.Add("MFA_SSPR")
        } else {
            # --- MODO AGREGADO: APIs de resumen para tenants grandes (>500 licenciados) ---
            $FeatureReport = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByFeature(includedUserTypes='member',includedUserRoles='all')"
            $MethodReport  = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByMethod(includedUserTypes='member',includedUserRoles='all')"

            if ($FeatureReport -and $FeatureReport.totalUserCount) {
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
                    Registered       = $MfaCapable
                    NotRegistered    = $TotalAuthUsers - $MfaCapable
                    TotalUsers       = $TotalAuthUsers
                    PctRegistered    = $MfaPct
                    MfaCapable       = $MfaCapable
                    LicRegistered    = $MfaCapable
                    LicTotal         = $TotalAuthUsers
                    LicPctRegistered = $MfaPct
                }
                $EntraData.SSPR = @{
                    Registered       = $SsprRegistered
                    NotRegistered    = $TotalAuthUsers - $SsprRegistered
                    Enabled          = $SsprEnabled
                    TotalUsers       = $TotalAuthUsers
                    PctRegistered    = $SsprPct
                    LicRegistered    = $SsprRegistered
                    LicTotal         = $TotalAuthUsers
                    LicPctRegistered = $SsprPct
                }
                Write-OK "MFA:  $MfaCapable/$TotalAuthUsers members capable ($MfaPct%)"
                Write-OK "SSPR: $SsprRegistered/$TotalAuthUsers members registrados ($SsprPct%)"

                # Metodos de autenticacion desde API agregada
                $MethodCounts = @{ Authenticator = 0; PhoneAuth = 0; FIDO2 = 0; Email = 0; WHfB = 0; Passwordless = 0 }
                if ($MethodReport -and $MethodReport.userRegistrationMethodCounts) {
                    foreach ($M in $MethodReport.userRegistrationMethodCounts) {
                        switch ($M.authenticationMethod) {
                            "microsoftAuthenticatorPush"         { $MethodCounts.Authenticator = [int]$M.userCount }
                            "mobilePhone"                        { $MethodCounts.PhoneAuth     = [int]$M.userCount }
                            "fido2SecurityKey"                    { $MethodCounts.FIDO2         = [int]$M.userCount }
                            "email"                              { $MethodCounts.Email          = [int]$M.userCount }
                            "windowsHelloForBusiness"            { $MethodCounts.WHfB           = [int]$M.userCount }
                            "microsoftAuthenticatorPasswordless" { $MethodCounts.Passwordless  += [int]$M.userCount }
                            "passKeyDeviceBound"                 { $MethodCounts.Passwordless  += [int]$M.userCount }
                            "passKeySynced"                      { $MethodCounts.Passwordless  += [int]$M.userCount }
                        }
                    }
                }
                $EntraData.AuthMethods = $MethodCounts
                $EntraData.AuthMethodsLicensed = $MethodCounts
                Write-OK "Metodos (members): Auth=$($MethodCounts.Authenticator), Phone=$($MethodCounts.PhoneAuth), FIDO2=$($MethodCounts.FIDO2), WHfB=$($MethodCounts.WHfB)"

                $ModulesExecuted.Add("MFA_SSPR")
            } else {
                Write-Warn "No se obtuvieron datos de registro de MFA/SSPR"
            }
        }
    } catch {
        Write-Warn "No se pudo obtener estado de MFA/SSPR: $_"
    }

    $Result.Entra = $EntraData
} else {
    Write-Skip "Entra ID P1 no detectado - saltando modulo"
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
        $RiskyCount = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/`$count" -Method GET
        $RiskyHighResp   = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'high' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1" -Method GET
        $RiskyMediumResp = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'medium' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1" -Method GET
        $RiskyLowResp    = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'low' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&`$count=true&`$top=1" -Method GET

        $RiskyHigh   = if ($RiskyHighResp -and $RiskyHighResp.ContainsKey('@odata.count')) { [int]$RiskyHighResp['@odata.count'] } else { @($RiskyHighResp.value).Count }
        $RiskyMedium = if ($RiskyMediumResp -and $RiskyMediumResp.ContainsKey('@odata.count')) { [int]$RiskyMediumResp['@odata.count'] } else { @($RiskyMediumResp.value).Count }
        $RiskyLow    = if ($RiskyLowResp -and $RiskyLowResp.ContainsKey('@odata.count')) { [int]$RiskyLowResp['@odata.count'] } else { @($RiskyLowResp.value).Count }
        $RiskyTotal  = $RiskyHigh + $RiskyMedium + $RiskyLow

        # Detectar si hay CA policies basadas en riesgo (sign-in risk / user risk)
        # Reusar $CaPolicies de Fase 2 (evita llamada API duplicada)
        $HasSignInRiskPolicy = $false
        $HasUserRiskPolicy   = $false
        if ($CaPolicies) {
            foreach ($CaPol in $CaPolicies) {
                if ($CaPol.state -ne 'enabled') { continue }
                $SignInRiskLevels = $CaPol.conditions.signInRiskLevels
                $UserRiskLevels   = $CaPol.conditions.userRiskLevels
                if ($SignInRiskLevels -and $SignInRiskLevels.Count -gt 0) { $HasSignInRiskPolicy = $true }
                if ($UserRiskLevels -and $UserRiskLevels.Count -gt 0) { $HasUserRiskPolicy = $true }
            }
        }

        $Result.Entra.RiskyUsers = @{
            TotalAtRisk          = $RiskyTotal
            High                 = $RiskyHigh
            Medium               = $RiskyMedium
            Low                  = $RiskyLow
            HasSignInRiskPolicy  = $HasSignInRiskPolicy
            HasUserRiskPolicy    = $HasUserRiskPolicy
        }
        $RiskyColor = if ($RiskyHigh -gt 0) { "Red" } elseif ($RiskyMedium -gt 0) { "Yellow" } else { "Green" }
        Write-Host "  [OK] Usuarios riesgosos: $RiskyTotal (High:$RiskyHigh, Medium:$RiskyMedium, Low:$RiskyLow)" -ForegroundColor $RiskyColor
        Write-OK "Risk Policies: SignInRisk=$HasSignInRiskPolicy, UserRisk=$HasUserRiskPolicy"
        $ModulesExecuted.Add("RiskyUsers")
    } catch {
        Write-Warn "No se pudo obtener usuarios riesgosos: $_"
    }

    # --- PIM: Roles elegibles ---
    Write-Step "Obteniendo roles de PIM..."
    try {
        $PimEligible = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
        $PimActive   = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances"

        # Obtener definiciones de roles para nombres legibles
        $RoleDefs = @{}
        try {
            $RoleDefsRaw = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
            foreach ($RD in $RoleDefsRaw) { $RoleDefs[$RD.id] = $RD.displayName }
        } catch { Write-Warn "No se pudieron obtener definiciones de roles" }

        # Clasificar principals: resolver tipo via directoryObjects
        $AllPrincipalIds = @($PimActive | ForEach-Object { $_.principalId }) + @($PimEligible | ForEach-Object { $_.principalId }) | Sort-Object -Unique
        $PrincipalTypes = @{}
        $PrincipalNames = @{}
        # Consultar en lotes de 15
        for ($i = 0; $i -lt $AllPrincipalIds.Count; $i += 15) {
            $Batch = $AllPrincipalIds[$i..([Math]::Min($i + 14, $AllPrincipalIds.Count - 1))]
            $Body = @{ ids = $Batch; types = @("user","servicePrincipal","group") } | ConvertTo-Json -Depth 3
            try {
                $Resolved = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" -Body $Body -ContentType "application/json"
                foreach ($Obj in $Resolved.value) {
                    $OType = $Obj['@odata.type']
                    $PrincipalTypes[$Obj.id] = switch ($OType) {
                        '#microsoft.graph.user'             { 'User' }
                        '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
                        '#microsoft.graph.group'            { 'Group' }
                        default                             { 'Other' }
                    }
                    $PrincipalNames[$Obj.id] = if ($Obj.displayName) { $Obj.displayName } else { $Obj.id }
                }
            } catch { <# silently continue #> }
        }

        # Contar roles unicos
        $EligibleRoles  = @($PimEligible | ForEach-Object { $_.roleDefinitionId } | Sort-Object -Unique).Count
        $ActiveRoles    = @($PimActive | ForEach-Object { $_.roleDefinitionId } | Sort-Object -Unique).Count

        # Desglose por tipo de principal
        $ActiveByType = @{ User = 0; ServicePrincipal = 0; Group = 0; Other = 0 }
        $ActiveUserIds = [System.Collections.Generic.HashSet[string]]::new()
        $ActiveSPIds   = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($A2 in $PimActive) {
            $PType = if ($PrincipalTypes.ContainsKey($A2.principalId)) { $PrincipalTypes[$A2.principalId] } else { 'Other' }
            if ($PType -eq 'User') { [void]$ActiveUserIds.Add($A2.principalId) }
            elseif ($PType -eq 'ServicePrincipal') { [void]$ActiveSPIds.Add($A2.principalId) }
        }
        $ActiveByType.User = $ActiveUserIds.Count
        $ActiveByType.ServicePrincipal = $ActiveSPIds.Count
        $TotalUniquePrincipals = @($PimActive | ForEach-Object { $_.principalId } | Sort-Object -Unique).Count
        $ActiveByType.Group = $TotalUniquePrincipals - $ActiveByType.User - $ActiveByType.ServicePrincipal
        if ($ActiveByType.Group -lt 0) { $ActiveByType.Group = 0 }

        $EligibleUserIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($E2 in $PimEligible) {
            $PType = if ($PrincipalTypes.ContainsKey($E2.principalId)) { $PrincipalTypes[$E2.principalId] } else { 'Other' }
            if ($PType -eq 'User') { [void]$EligibleUserIds.Add($E2.principalId) }
        }

        # Permanentes (Assigned sin fecha de fin)
        $TrulyPermanent = @($PimActive | Where-Object {
            $_.assignmentType -eq 'Assigned' -and (-not $_.endDateTime -or [string]::IsNullOrEmpty($_.endDateTime))
        })
        $PermUserIds = [System.Collections.Generic.HashSet[string]]::new()
        $PermSPIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($P2 in $TrulyPermanent) {
            $PType = if ($PrincipalTypes.ContainsKey($P2.principalId)) { $PrincipalTypes[$P2.principalId] } else { 'Other' }
            if ($PType -eq 'User') { [void]$PermUserIds.Add($P2.principalId) }
            elseif ($PType -eq 'ServicePrincipal') { [void]$PermSPIds.Add($P2.principalId) }
        }

        # Top roles con mas asignaciones permanentes de usuarios humanos
        $TopPermRoles = @{}
        foreach ($P2 in $TrulyPermanent) {
            $PType = if ($PrincipalTypes.ContainsKey($P2.principalId)) { $PrincipalTypes[$P2.principalId] } else { 'Other' }
            if ($PType -eq 'User') {
                $RName = if ($RoleDefs.ContainsKey($P2.roleDefinitionId)) { $RoleDefs[$P2.roleDefinitionId] } else { $P2.roleDefinitionId }
                if (-not $TopPermRoles.ContainsKey($RName)) { $TopPermRoles[$RName] = 0 }
                $TopPermRoles[$RName]++
            }
        }
        $TopPermRolesList = @($TopPermRoles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { @{ Role = $_.Key; Count = $_.Value } })

        $Result.Entra.PIM = @{
            EligibleAssignments  = $PimEligible.Count
            EligibleRoles        = $EligibleRoles
            EligibleUsers        = $EligibleUserIds.Count
            ActiveAssignments    = $PimActive.Count
            ActiveRoles          = $ActiveRoles
            ActiveUsers          = $ActiveUserIds.Count
            ActiveSPs            = $ActiveSPIds.Count
            ActiveTotal          = $TotalUniquePrincipals
            PermanentAssignments = $TrulyPermanent.Count
            PermanentUsers       = $PermUserIds.Count
            PermanentSPs         = $PermSPIds.Count
            TopPermanentRoles    = $TopPermRolesList
        }
        Write-OK "PIM: $($PimEligible.Count) elegibles ($($EligibleUserIds.Count) usuarios humanos)"
        Write-OK "PIM: $($PimActive.Count) activas - $($ActiveUserIds.Count) usuarios, $($ActiveSPIds.Count) service principals, $($ActiveByType.Group) grupos"
        Write-OK "PIM: $($TrulyPermanent.Count) permanentes ($($PermUserIds.Count) usuarios, $($PermSPIds.Count) SPs)"
        $ModulesExecuted.Add("PIM")
    } catch {
        Write-Warn "No se pudo obtener datos de PIM: $_"
    }

    # --- Access Reviews ---
    if ($HasEntraGov) {
        Write-Step "Obteniendo Access Reviews..."
        try {
            # @() ensures $Reviews is always an array even if Get-AllGraphPages returns empty (StrictMode safety)
            $Reviews = @(Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions")
            $ReviewsActive = @($Reviews | Where-Object { $_.status -eq "InProgress" }).Count
            $ReviewsCompleted = @($Reviews | Where-Object { $_.status -eq "Completed" }).Count

            $Result.Entra.AccessReviews = @{
                Total     = $Reviews.Count
                Active    = $ReviewsActive
                Completed = $ReviewsCompleted
            }
            Write-OK "Access Reviews: $($Reviews.Count) total ($ReviewsActive activas, $ReviewsCompleted completadas)"
            $ModulesExecuted.Add("AccessReviews")
        } catch {
            Write-Warn "No se pudo obtener Access Reviews: $_"
        }
    }
} else {
    Write-Skip "Entra ID P2 no detectado - saltando modulo"
}

# ============================================================================
# FASE 4: ADVANCED HUNTING (MDE, MDO, MDA, MDI)
# ============================================================================
if ($HasAdvHunting) {
    Write-Section "Fase 4: Advanced Hunting (MDE, MDO, MDA, MDI)"

    # Verificar acceso a Advanced Hunting con una query generica (1 solo intento)
    Write-Step "Verificando acceso a Advanced Hunting..."
    $KQLAvailable = $false
    try {
        $TestBody = @{ Query = "AlertInfo | take 1" } | ConvertTo-Json
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
    }
}

if ($HasAdvHunting -and $KQLAvailable) {

    # --- MDE ---
    if ($HasMDE) {
        Write-Step "Consultando MDE - Dispositivos onboarded..."
        try {
            # Dispositivos onboarded unicos (ultimos 30d)
            $MdeDevices = Invoke-KQL -Query @"
DeviceInfo
| where Timestamp > ago(30d)
| where OnboardingStatus == "Onboarded"
| summarize LastSeen = max(Timestamp) by DeviceId, DeviceName, OSPlatform
| summarize
    TotalDevices = dcount(DeviceId),
    Windows = dcountif(DeviceId, OSPlatform has "Windows"),
    MacOS = dcountif(DeviceId, OSPlatform has "macOS"),
    Linux = dcountif(DeviceId, OSPlatform has "Linux"),
    iOS = dcountif(DeviceId, OSPlatform has "iOS"),
    Android = dcountif(DeviceId, OSPlatform has "Android")
"@

            # Usuarios unicos con dispositivo MDE
            $MdeUsers = Invoke-KQL -Query @"
DeviceInfo
| where Timestamp > ago(30d)
| where OnboardingStatus == "Onboarded"
| mv-expand LoggedOnUsers
| extend UserSid = tostring(LoggedOnUsers.Sid)
| where isnotempty(UserSid)
| summarize UniqueUsers = dcount(UserSid)
"@

            # Dispositivos sin senal 7+ dias
            $MdeStale = Invoke-KQL -Query @"
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize LastSeen = max(Timestamp) by DeviceId
| where LastSeen < ago(7d)
| summarize StaleDevices = count()
"@

            # Alertas MDE ultimos 30 dias
            $MdeAlerts = Invoke-KQL -Query @"
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Defender for Endpoint"
| summarize
    Total = count(),
    High = countif(Severity == "High"),
    Medium = countif(Severity == "Medium"),
    Low = countif(Severity == "Low"),
    Informational = countif(Severity == "Informational")
"@

            # Licencias MDE del Script 1
            $MdeLicensedUsers = 0
            if ($LicData.Adoption) {
                $MdeAdoption = $LicData.Adoption | Where-Object { $_.Product -eq "MDE_P2" -or $_.Product -eq "MDE_P1" } | Select-Object -First 1
                if ($MdeAdoption) { $MdeLicensedUsers = $MdeAdoption.UsersEnabled + $MdeAdoption.UsersDisabled }
            }

            $DeviceCount = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].TotalDevices } else { 0 }
            $UserCount   = if ($MdeUsers -and $MdeUsers[0]) { [int]$MdeUsers[0].UniqueUsers } else { 0 }
            $StaleCount  = if ($MdeStale -and $MdeStale[0]) { [int]$MdeStale[0].StaleDevices } else { 0 }
            $CoveragePct = if ($MdeLicensedUsers -gt 0) { [math]::Round(($UserCount / $MdeLicensedUsers) * 100, 1) } else { 0 }
            $AvgDevices  = if ($UserCount -gt 0) { [math]::Round($DeviceCount / $UserCount, 1) } else { 0 }

            $Result.MDE = @{
                DevicesOnboarded     = $DeviceCount
                UniqueUsersWithDevice = $UserCount
                UsersWithLicense     = $MdeLicensedUsers
                CoveragePct          = $CoveragePct
                UsersWithoutCoverage = [math]::Max(0, $MdeLicensedUsers - $UserCount)
                AvgDevicesPerUser    = $AvgDevices
                DevicesStale7d       = $StaleCount
                Platforms            = @{
                    Windows = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].Windows } else { 0 }
                    MacOS   = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].MacOS } else { 0 }
                    Linux   = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].Linux } else { 0 }
                    iOS     = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].iOS } else { 0 }
                    Android = if ($MdeDevices -and $MdeDevices[0]) { [int]$MdeDevices[0].Android } else { 0 }
                }
                Alerts30d            = @{
                    Total         = if ($MdeAlerts -and $MdeAlerts[0]) { [int]$MdeAlerts[0].Total } else { 0 }
                    High          = if ($MdeAlerts -and $MdeAlerts[0]) { [int]$MdeAlerts[0].High } else { 0 }
                    Medium        = if ($MdeAlerts -and $MdeAlerts[0]) { [int]$MdeAlerts[0].Medium } else { 0 }
                    Low           = if ($MdeAlerts -and $MdeAlerts[0]) { [int]$MdeAlerts[0].Low } else { 0 }
                    Informational = if ($MdeAlerts -and $MdeAlerts[0]) { [int]$MdeAlerts[0].Informational } else { 0 }
                }
            }
            Write-OK "MDE: $DeviceCount dispositivos onboarded, $UserCount usuarios ($CoveragePct% cobertura), $StaleCount stale"
            Write-OK "MDE Alertas 30d: $(if($MdeAlerts -and $MdeAlerts[0]){$MdeAlerts[0].Total}else{0})"
            $ModulesExecuted.Add("MDE")
        } catch {
            Write-Warn "Error consultando MDE: $_"
        }
    } else {
        Write-Skip "MDE no detectado - saltando"
    }

    # --- MDO ---
    if ($HasMDO) {
        Write-Step "Consultando MDO - Proteccion de correo..."
        try {
            $MdoStats = Invoke-KQL -Query @"
EmailEvents
| where Timestamp > ago(30d)
| summarize
    TotalEmails = count(),
    Phishing = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    DeliveredToInbox = countif(DeliveryAction == "Delivered"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Junked = countif(DeliveryAction == "Junked")
"@

            $MdoSafeLinks = Invoke-KQL -Query @"
UrlClickEvents
| where Timestamp > ago(30d)
| summarize
    TotalClicks = count(),
    Blocked = countif(ActionType == "ClickBlocked"),
    Allowed = countif(ActionType == "ClickAllowed"),
    PendingDetonation = countif(ActionType == "UrlClickPendingDetonation")
"@

            $MdoAlerts = Invoke-KQL -Query @"
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Defender for Office 365"
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            $Result.MDO = @{
                EmailsProcessed30d = if ($MdoStats -and $MdoStats[0]) { [long]$MdoStats[0].TotalEmails } else { 0 }
                PhishingDetected   = if ($MdoStats -and $MdoStats[0]) { [int]$MdoStats[0].Phishing } else { 0 }
                MalwareDetected    = if ($MdoStats -and $MdoStats[0]) { [int]$MdoStats[0].Malware } else { 0 }
                SpamDetected       = if ($MdoStats -and $MdoStats[0]) { [int]$MdoStats[0].Spam } else { 0 }
                Blocked            = if ($MdoStats -and $MdoStats[0]) { [int]$MdoStats[0].Blocked } else { 0 }
                SafeLinks          = @{
                    TotalClicks = if ($MdoSafeLinks -and $MdoSafeLinks[0]) { [int]$MdoSafeLinks[0].TotalClicks } else { 0 }
                    Blocked     = if ($MdoSafeLinks -and $MdoSafeLinks[0]) { [int]$MdoSafeLinks[0].Blocked } else { 0 }
                    Allowed     = if ($MdoSafeLinks -and $MdoSafeLinks[0]) { [int]$MdoSafeLinks[0].Allowed } else { 0 }
                }
                Alerts30d          = @{
                    Total  = if ($MdoAlerts -and $MdoAlerts[0]) { [int]$MdoAlerts[0].Total } else { 0 }
                    High   = if ($MdoAlerts -and $MdoAlerts[0]) { [int]$MdoAlerts[0].High } else { 0 }
                    Medium = if ($MdoAlerts -and $MdoAlerts[0]) { [int]$MdoAlerts[0].Medium } else { 0 }
                }
            }
            Write-OK "MDO: $(if($MdoStats -and $MdoStats[0]){$MdoStats[0].TotalEmails}else{0}) emails procesados, $(if($MdoStats -and $MdoStats[0]){$MdoStats[0].Phishing}else{0}) phishing detectado"
            Write-OK "Safe Links: $(if($MdoSafeLinks -and $MdoSafeLinks[0]){$MdoSafeLinks[0].Blocked}else{0}) clicks bloqueados"
            $ModulesExecuted.Add("MDO")
        } catch {
            Write-Warn "Error consultando MDO: $_"
        }
    } else {
        Write-Skip "MDO no detectado - saltando"
    }

    # --- MDA ---
    if ($HasMDA) {
        Write-Step "Consultando MDA - Cloud App Security..."
        try {
            $MdaStats = Invoke-KQL -Query @"
CloudAppEvents
| where Timestamp > ago(30d)
| summarize
    TotalEvents = count(),
    UniqueApps = dcount(Application),
    UniqueUsers = dcount(AccountObjectId)
"@

            $MdaAlerts = Invoke-KQL -Query @"
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Cloud App Security"
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            # Top apps monitoreadas
            $MdaTopApps = Invoke-KQL -Query @"
CloudAppEvents
| where Timestamp > ago(30d)
| summarize Events = count() by Application
| top 10 by Events desc
"@

            $Result.MDA = @{
                Events30d      = if ($MdaStats -and $MdaStats[0]) { [long]$MdaStats[0].TotalEvents } else { 0 }
                UniqueApps     = if ($MdaStats -and $MdaStats[0]) { [int]$MdaStats[0].UniqueApps } else { 0 }
                UniqueUsers    = if ($MdaStats -and $MdaStats[0]) { [int]$MdaStats[0].UniqueUsers } else { 0 }
                TopApps        = @($MdaTopApps | ForEach-Object { @{ App = $_.Application; Events = [int]$_.Events } })
                Alerts30d      = @{
                    Total  = if ($MdaAlerts -and $MdaAlerts[0]) { [int]$MdaAlerts[0].Total } else { 0 }
                    High   = if ($MdaAlerts -and $MdaAlerts[0]) { [int]$MdaAlerts[0].High } else { 0 }
                    Medium = if ($MdaAlerts -and $MdaAlerts[0]) { [int]$MdaAlerts[0].Medium } else { 0 }
                }
            }
            Write-OK "MDA: $(if($MdaStats -and $MdaStats[0]){$MdaStats[0].UniqueApps}else{0}) apps monitoreadas, $(if($MdaStats -and $MdaStats[0]){$MdaStats[0].TotalEvents}else{0}) eventos 30d"
            $ModulesExecuted.Add("MDA")
        } catch {
            Write-Warn "Error consultando MDA: $_"
        }
    } else {
        Write-Skip "MDA no detectado - saltando"
    }

    # --- MDI ---
    if ($HasMDI) {
        Write-Step "Consultando MDI - Defender for Identity..."
        try {
            # DCs monitoreados
            $MdiDCs = Invoke-KQL -Query @"
IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize LastSeen = max(Timestamp), Events = count() by DeviceName
| order by Events desc
"@

            # Volumen de eventos
            $MdiStats = Invoke-KQL -Query @"
IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize
    TotalEvents = count(),
    UniqueUsers = dcount(AccountUpn),
    SuccessLogons = countif(ActionType == "LogonSuccess"),
    FailedLogons = countif(ActionType == "LogonFailed")
"@

            # Alertas MDI
            $MdiAlerts = Invoke-KQL -Query @"
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Defender for Identity"
| summarize Total = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium")
"@

            $DCList = @($MdiDCs | ForEach-Object {
                @{
                    Name     = $_.DeviceName
                    LastSeen = $_.LastSeen
                    Events   = [int]$_.Events
                }
            })

            $Result.MDI = @{
                DCsMonitored     = $DCList.Count
                DCDetails        = $DCList
                LogonEvents30d   = if ($MdiStats -and $MdiStats[0]) { [long]$MdiStats[0].TotalEvents } else { 0 }
                UniqueUsers      = if ($MdiStats -and $MdiStats[0]) { [int]$MdiStats[0].UniqueUsers } else { 0 }
                SuccessLogons    = if ($MdiStats -and $MdiStats[0]) { [long]$MdiStats[0].SuccessLogons } else { 0 }
                FailedLogons     = if ($MdiStats -and $MdiStats[0]) { [long]$MdiStats[0].FailedLogons } else { 0 }
                Alerts30d        = @{
                    Total  = if ($MdiAlerts -and $MdiAlerts[0]) { [int]$MdiAlerts[0].Total } else { 0 }
                    High   = if ($MdiAlerts -and $MdiAlerts[0]) { [int]$MdiAlerts[0].High } else { 0 }
                    Medium = if ($MdiAlerts -and $MdiAlerts[0]) { [int]$MdiAlerts[0].Medium } else { 0 }
                }
                Note             = "Validar con el cliente el total de DCs del dominio para confirmar cobertura completa"
            }
            Write-OK "MDI: $($DCList.Count) DCs monitoreados, $(if($MdiStats -and $MdiStats[0]){$MdiStats[0].TotalEvents}else{0}) logon events 30d"
            Write-OK "MDI: $(if($MdiStats -and $MdiStats[0]){$MdiStats[0].FailedLogons}else{0}) logons fallidos detectados"
            $ModulesExecuted.Add("MDI")
        } catch {
            Write-Warn "Error consultando MDI: $_"
        }
    } else {
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

try {
    $ScoreData = $null
    $LatestScoreFile = Get-ChildItem -Path $OutputPath -Filter "*_secure_score.json" | Sort-Object Name -Descending | Select-Object -First 1
    if ($LatestScoreFile) {
        $ScoreData = Get-Content $LatestScoreFile.FullName -Raw | ConvertFrom-Json
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
                        EmailsProcessed30d = 0; PhishingDetected = 0; MalwareDetected = 0
                        SpamDetected = 0; Blocked = 0
                        SafeLinks = @{ TotalClicks = 0; Blocked = 0; Allowed = 0 }
                        Alerts30d = @{ Total = 0; High = 0; Medium = 0 }
                        Note = "Datos KQL no disponibles. Configuracion evaluada via Secure Score."
                    }
                } elseif ($ProductKey -eq "MDA") {
                    $Result.MDA = @{
                        UniqueApps = 0; Events30d = 0; UniqueUsers = 0
                        Alerts30d = @{ Total = 0; High = 0; Medium = 0 }
                        Note = "Datos KQL no disponibles. Configuracion evaluada via Secure Score."
                    }
                } elseif ($ProductKey -eq "MDE") {
                    $Result.MDE = @{
                        DevicesOnboarded = 0; CoveragePct = 0; UniqueUsersWithDevice = 0
                        UsersWithLicense = 0; DevicesStale7d = 0
                        Alerts30d = @{ Total = 0; High = 0; Medium = 0 }
                        Note = "Datos KQL no disponibles. Configuracion evaluada via Secure Score."
                    }
                } elseif ($ProductKey -eq "MDI") {
                    $Result.MDI = @{
                        DCsMonitored = 0; LogonEvents30d = 0; FailedLogons = 0; SuccessLogons = 0
                        UniqueUsers = 0; Alerts30d = @{ Total = 0; High = 0; Medium = 0 }
                        Note = "Datos KQL no disponibles. Configuracion evaluada via Secure Score."
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
            $Partial  = @($Controls | Where-Object { $_.CurrentScore -gt 0 -and $_.CurrentScore -lt $_.MaxScore }).Count
            $NotImpl  = $Controls.Count - $Enabled - $Partial

            $Result[$ProductKey].SecureScoreControls = @{
                Total          = $Controls.Count
                FullyEnabled   = $Enabled
                Partial        = $Partial
                NotImplemented = $NotImpl
                Details        = @($Controls | ForEach-Object {
                    $Pct = if ($_.MaxScore -gt 0) { [math]::Round($_.CurrentScore / $_.MaxScore * 100) } else { 0 }
                    [PSCustomObject]@{
                        Title                = $_.Title
                        ScoreInPercentage    = $Pct
                        ImplementationStatus = $_.ImplementationStatus
                        Improvement          = $_.Improvement
                        Category             = $_.Category
                        Service              = $SvcName
                    }
                } | Sort-Object ScoreInPercentage -Descending)
            }
            Write-OK "$ProductKey Secure Score: $Enabled/$($Controls.Count) controles completados, $Partial parciales, $NotImpl pendientes"
        }
    } else {
        Write-Warn "No se encontro archivo de Secure Score en $OutputPath"
    }
} catch {
    Write-Warn "Error analizando Secure Score: $_"
}

# ============================================================================
# FASE 5: INTUNE
# ============================================================================
if ($HasIntune) {
    Write-Section "Fase 5: Microsoft Intune"

    Write-Step "Obteniendo estadisticas de Intune (APIs de conteo)..."
    try {
        # LIGHTWEIGHT: Usar $top=1 con $count=true para obtener conteos sin paginar
        $TotalDevices = 0
        $TotalResp = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$top=1&`$count=true&`$select=id" -Method GET
        if ($TotalResp -and $TotalResp.ContainsKey('@odata.count')) { $TotalDevices = [int]$TotalResp['@odata.count'] }
        elseif ($TotalResp -and $TotalResp.value) { $TotalDevices = $TotalResp.value.Count }

        if ($TotalDevices -gt 0) {
            # Obtener compliance y plataformas de 1 pagina (max 999 devices)
            # Para tenants grandes esto es una muestra representativa
            $DevicesSample = Invoke-GraphSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=complianceState,operatingSystem,lastSyncDateTime&`$top=999" -Method GET

            $Compliant = 0; $NonCompliant = 0; $StaleDevices = 0
            $Platforms = @{}
            $SampleSize = 0
            $StaleDate = (Get-Date).AddDays(-$InactiveDays)

            if ($DevicesSample -and $DevicesSample.value) {
                $SampleSize = $DevicesSample.value.Count
                foreach ($D in $DevicesSample.value) {
                    if ($D.complianceState -eq "compliant") { $Compliant++ }
                    elseif ($D.complianceState -eq "noncompliant") { $NonCompliant++ }
                    $OS = if ($D.operatingSystem) { $D.operatingSystem } else { "Unknown" }
                    if (-not $Platforms.ContainsKey($OS)) { $Platforms[$OS] = 0 }
                    $Platforms[$OS]++
                    if ($D.lastSyncDateTime -and ([datetime]$D.lastSyncDateTime -lt $StaleDate)) { $StaleDevices++ }
                }
                # Si la muestra es menor que el total, escalar proporcionalmente
                if ($SampleSize -lt $TotalDevices -and $SampleSize -gt 0) {
                    $Scale = $TotalDevices / $SampleSize
                    $Compliant    = [math]::Round($Compliant * $Scale)
                    $NonCompliant = [math]::Round($NonCompliant * $Scale)
                    $StaleDevices = [math]::Round($StaleDevices * $Scale)
                    foreach ($Key in @($Platforms.Keys)) {
                        $Platforms[$Key] = [math]::Round($Platforms[$Key] * $Scale)
                    }
                }
            }
            $Unknown = $TotalDevices - $Compliant - $NonCompliant
            $CompliancePct = if ($TotalDevices -gt 0) { [math]::Round(($Compliant / $TotalDevices) * 100, 1) } else { 0 }

            # Licencias Intune del Script 1
            $IntuneLicensedUsers = 0
            if ($LicData.Adoption) {
                $IntuneAdoption = $LicData.Adoption | Where-Object { $_.Product -eq "Intune_P1" } | Select-Object -First 1
                if ($IntuneAdoption) { $IntuneLicensedUsers = $IntuneAdoption.UsersEnabled + $IntuneAdoption.UsersDisabled }
            }

            $Result.Intune = @{
                DevicesEnrolled  = $TotalDevices
                Compliant        = $Compliant
                NonCompliant     = $NonCompliant
                Unknown          = $Unknown
                CompliancePct    = $CompliancePct
                Stale30d         = $StaleDevices
                UsersWithLicense = $IntuneLicensedUsers
                Platforms        = $Platforms
                Ownership        = @{ Corporate = 0; Personal = 0 }
            }

            $CompColor = if ($CompliancePct -ge 80) { "Green" } elseif ($CompliancePct -ge 50) { "Yellow" } else { "Red" }
            Write-Host "  [OK] Intune: $TotalDevices dispositivos enrolled ($CompliancePct% compliant)" -ForegroundColor $CompColor
            Write-OK "Plataformas: $(($Platforms.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ', ')"
            Write-OK "Stale ${InactiveDays}d+: $StaleDevices dispositivos"
            $ModulesExecuted.Add("Intune")
        } else {
            Write-Warn "No se pudieron obtener conteos de Intune (Total=0)"
        }
    } catch {
        Write-Warn "Error consultando Intune: $_"
    }
} else {
    Write-Skip "Intune no detectado - saltando"
}

# ============================================================================
# FASE 6: COPILOT
# ============================================================================
if ($HasCopilot) {
    Write-Section "Fase 6: Microsoft 365 Copilot"

    Write-Step "Obteniendo uso de Copilot (ultimos 30 dias)..."
    try {
        $CopilotReport = Invoke-GraphSafe -Uri "https://graph.microsoft.com/beta/reports/getMicrosoft365CopilotUsageUserDetail(period='D30')?`$format=application/json"

        if ($CopilotReport -and $CopilotReport.value) {
            $CopilotUsers    = $CopilotReport.value
            $TotalCopilot    = $CopilotUsers.Count
            $ActiveCopilot   = @($CopilotUsers | Where-Object {
                $_.copilotActivityUserDetailsByPeriod -and
                ($_.copilotActivityUserDetailsByPeriod | Where-Object { $_.hasAnyActivity -eq $true })
            }).Count

            # Licencias Copilot del Script 1
            $CopilotLicensed = 0
            if ($LicData.Adoption) {
                $CopAdoption = $LicData.Adoption | Where-Object { $_.Product -eq "Copilot_M365" } | Select-Object -First 1
                if ($CopAdoption) { $CopilotLicensed = $CopAdoption.UsersEnabled }
            }

            $CopilotPct = if ($CopilotLicensed -gt 0) { [math]::Round(($ActiveCopilot / $CopilotLicensed) * 100, 1) } else { 0 }

            $Result.Copilot = @{
                LicensedUsers    = $CopilotLicensed
                TotalInReport    = $TotalCopilot
                ActiveUsers30d   = $ActiveCopilot
                AdoptionPct      = $CopilotPct
            }
            Write-OK "Copilot: $ActiveCopilot/$CopilotLicensed usuarios activos ($CopilotPct%)"
        } else {
            Write-Warn "No se obtuvieron datos de uso de Copilot"
        }
        $ModulesExecuted.Add("Copilot")
    } catch {
        Write-Warn "Error consultando Copilot: $_"
    }
} else {
    Write-Skip "Copilot no detectado - saltando"
}

# ============================================================================
# FASE 7: EXPORTAR JSON
# ============================================================================
Write-Section "Fase 7: Exportando resultados"

$Result.ModulesExecuted = @($ModulesExecuted)

# --- Resumen de protecciones cubiertas por política ---
# Ciertos workloads protegen a TODOS los usuarios del tenant cuando las políticas están configuradas,
# independientemente de cuantas licencias esten asignadas individualmente:
#   - Entra ID P2 (Identity Protection): Risk policies aplican a todo sign-in
#   - MDO: Safe Links/Attachments/Anti-Phishing aplican a todo el mail flow
#   - MDI: Monitorea Domain Controllers, protege todo el Active Directory
#   - MDA: App Connectors, session policies, anomaly detection aplican a todo el trafico cloud
#   - Purview: DLP, Auto-Labeling, Retention policies aplican a ubicaciones completas
$TW = @{}

# Helper: busca controles clave por titulo (substring match) y devuelve su estado
function Get-PolicyStatus {
    param([hashtable]$ScoreControls, [string[]]$KeyPhrases)
    $Policies = @()
    if ($ScoreControls -and $ScoreControls.Details) {
        foreach ($Phrase in $KeyPhrases) {
            $Match = $ScoreControls.Details | Where-Object { $_.Title -like "*$Phrase*" } | Select-Object -First 1
            if ($Match) {
                $Policies += @{
                    Name   = $Match.Title
                    Active = ($Match.ImplementationStatus -eq "Implemented")
                }
            }
        }
    }
    return $Policies
}

# --- Entra ID P2: Risk-based Conditional Access ---
if ($Result.ContainsKey('Entra') -and $Result.Entra) {
    $RU = $Result.Entra.RiskyUsers
    if ($RU) {
        $TW["Entra_ID_P2"] = @{
            SignInRiskPolicy = [bool]$RU.HasSignInRiskPolicy
            UserRiskPolicy   = [bool]$RU.HasUserRiskPolicy
            Active           = [bool]($RU.HasSignInRiskPolicy -or $RU.HasUserRiskPolicy)
            Policies         = @(
                @{ Name = "Sign-in Risk Policy"; Active = [bool]$RU.HasSignInRiskPolicy }
                @{ Name = "User Risk Policy";   Active = [bool]$RU.HasUserRiskPolicy }
            )
        }
    }
}

# --- MDO: Safe Links, Safe Attachments, Anti-Phishing ---
if ($Result.ContainsKey('MDO') -and $Result.MDO) {
    $MdoSc = $Result.MDO.SecureScoreControls
    $MdoPolicies = @(Get-PolicyStatus -ScoreControls $MdoSc -KeyPhrases @(
        "Safe Attachments policy"
        "Safe Links policies"
        "anti-phishing policy"
        "zero-hour auto purge policies for phishing"
        "zero-hour auto purge policies for malware"
    ))
    $MdoActive = ($MdoPolicies | Where-Object { $_.Active }).Count -gt 0
    $TW["MDO_P1"] = @{
        Active   = $MdoActive
        Policies = $MdoPolicies
    }
    $TW["MDO_P2"] = $TW["MDO_P1"]
}

# --- MDI: Domain Controllers monitoreados ---
if ($Result.ContainsKey('MDI') -and $Result.MDI) {
    $MdiDCs = $Result.MDI.DCsMonitored
    $TW["MDI"] = @{
        Active       = [bool]($MdiDCs -gt 0)
        DCsMonitored = $MdiDCs
        Policies     = @(
            @{ Name = "Sensores en Domain Controllers"; Active = [bool]($MdiDCs -gt 0) }
        )
    }
}

# --- MDA: Cloud App Security policies ---
if ($Result.ContainsKey('MDA') -and $Result.MDA) {
    $MdaSc = $Result.MDA.SecureScoreControls
    $MdaPolicies = @(Get-PolicyStatus -ScoreControls $MdaSc -KeyPhrases @(
        "Defender for Cloud Apps is enabled"
        "log collector"
    ))
    $MdaActive = ($MdaPolicies | Where-Object { $_.Active }).Count -gt 0
    $TW["MDA"] = @{
        Active   = $MdaActive
        Policies = $MdaPolicies
    }
}

# --- Purview: DLP, Sensitivity Labels, Audit ---
if ($Result.ContainsKey('Purview') -and $Result.Purview) {
    $PvSc = $Result.Purview.SecureScoreControls
    $PvPolicies = @(Get-PolicyStatus -ScoreControls $PvSc -KeyPhrases @(
        "DLP policies are enabled"
        "sensitivity label"
        "audit log"
        "Auto-labeling"
    ))
    $PvActive = ($PvPolicies | Where-Object { $_.Active }).Count -gt 0
    # Solo una entrada "Purview" para la tarjeta de postura.
    # No agregamos entradas por subcategoria (Purview_DLP, Purview_AIP_P1, etc.)
    # porque el badge en la tabla de capacidad no aplica a cada componente individual.
    $TW["Purview"] = @{
        Active   = $PvActive
        Policies = $PvPolicies
    }
}
$Result.TenantWideProtection = $TW

$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$JsonPath  = Join-Path $OutputPath "${Timestamp}_security_adoption.json"
$Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-OK "JSON: $JsonPath"

# ============================================================================
# RESUMEN FINAL
# ============================================================================
$Duration = (Get-Date) - $ScriptStart

Write-Section "COMPLETADO en $([math]::Round($Duration.TotalSeconds)) segundos"
Write-Host "  Tenant:              $($LicData.TenantName) ($($LicData.TenantDomain))" -ForegroundColor Green
Write-Host "  Modulos ejecutados:  $($ModulesExecuted.Count) de 8" -ForegroundColor Green
Write-Host "  Modulos: $($ModulesExecuted -join ', ')" -ForegroundColor Gray
Write-Host "`n  Resultados en: $JsonPath" -ForegroundColor Cyan

# Resumen rapido de hallazgos
Write-Host "`n  Hallazgos clave:" -ForegroundColor White
if ($Result.ContainsKey('Entra') -and $Result.Entra) {
    if ($Result.Entra.ContainsKey('MFA') -and $Result.Entra.MFA) {
        $MfaColor = if ($Result.Entra.MFA.PctRegistered -ge 90) { "Green" } elseif ($Result.Entra.MFA.PctRegistered -ge 70) { "Yellow" } else { "Red" }
        Write-Host "    MFA Registration:     $($Result.Entra.MFA.PctRegistered)%" -ForegroundColor $MfaColor
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
    $MdeColor = if ($Result.MDE.CoveragePct -ge 80) { "Green" } elseif ($Result.MDE.CoveragePct -ge 50) { "Yellow" } else { "Red" }
    Write-Host "    MDE Cobertura:        $($Result.MDE.CoveragePct)% ($($Result.MDE.UniqueUsersWithDevice)/$($Result.MDE.UsersWithLicense) usuarios)" -ForegroundColor $MdeColor
}
if ($Result.ContainsKey('MDO') -and $Result.MDO) {
    Write-Host "    MDO Emails 30d:       $($Result.MDO.EmailsProcessed30d) (Phishing:$($Result.MDO.PhishingDetected))" -ForegroundColor Green
}
if ($Result.ContainsKey('MDA') -and $Result.MDA) {
    Write-Host "    MDA Apps monitoreadas:$($Result.MDA.UniqueApps)" -ForegroundColor $(if($Result.MDA.UniqueApps -gt 0){"Green"}else{"Yellow"})
}
if ($Result.ContainsKey('MDI') -and $Result.MDI) {
    Write-Host "    MDI DCs monitoreados: $($Result.MDI.DCsMonitored)" -ForegroundColor $(if($Result.MDI.DCsMonitored -gt 0){"Green"}else{"Red"})
}
if ($Result.ContainsKey('Intune') -and $Result.Intune) {
    $IntColor = if ($Result.Intune.CompliancePct -ge 80) { "Green" } elseif ($Result.Intune.CompliancePct -ge 50) { "Yellow" } else { "Red" }
    Write-Host "    Intune Compliance:    $($Result.Intune.CompliancePct)% ($($Result.Intune.Compliant)/$($Result.Intune.DevicesEnrolled))" -ForegroundColor $IntColor
}
if ($Result.ContainsKey('Copilot') -and $Result.Copilot) {
    Write-Host "    Copilot Adopcion:     $($Result.Copilot.AdoptionPct)% ($($Result.Copilot.ActiveUsers30d)/$($Result.Copilot.LicensedUsers))" -ForegroundColor $(if($Result.Copilot.AdoptionPct -ge 50){"Green"}else{"Yellow"})
}

Write-Host ""
if (-not $PreExistingSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion cerrada`n"
} else {
    Write-OK "Sesion mantenida (orquestador)`n"
}
