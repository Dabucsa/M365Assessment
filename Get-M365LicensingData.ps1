# Modulos requeridos: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Licensing Assessment Report v2
.DESCRIPTION
    Conecta al tenant via Microsoft Graph y genera un inventario completo de:
    - SKUs comprados vs asignados vs sin usar
    - Por usuario: features habilitados, deshabilitados, ultimo sign-in
    - Adoption por producto de seguridad (Entra, MDE, MDO, MDA, MDI, Intune, Purview)
    - Deteccion de desperdicio: cuentas deshabilitadas con licencia, sin sign-in 90+ dias
    - Deteccion de licencias duplicadas (ej: E5 + standalone MDE)
    - Asignacion por grupo vs directa
.PARAMETER TenantId
    ID del tenant. Si se omite, Graph usa el tenant del usuario que se autentica.
.PARAMETER OutputPath
    Carpeta de salida (default: .\output)
.PARAMETER InactiveDays
    Dias sin sign-in para considerar usuario inactivo (default: 90)
.EXAMPLE
    .\Get-MSLicensingReport.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
.NOTES
    Requiere: Global Reader (minimo)
    Modulos:  Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users
    Instalar: Install-Module Microsoft.Graph -Scope CurrentUser
              (o individualmente: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users)
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = ".\output",
    [int]$InactiveDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURACION: Mapeo ServicePlanName -> Categoria
# No usamos GUIDs hardcodeados. Los IDs se descubren dinamicamente desde los
# SKUs del tenant. Solo necesitamos conocer los NOMBRES de los service plans.
# ============================================================================
$PlanNameToCategory = @{
    # --- Entra ID (Azure AD) ---
    "AAD_PREMIUM"                       = "Entra_ID_P1"
    "AAD_PREMIUM_P2"                    = "Entra_ID_P2"
    "AAD_PREMIUM_P2_GOV"                = "Entra_ID_P2"
    "AAD_PREMIUM_GOV"                   = "Entra_ID_P1"
    "MFA_PREMIUM"                       = "Entra_ID_P1"
    "IDENTITY_GOVERNANCE"               = "Entra_ID_Governance"
    "AAD_PREMIUM_P2_GOVERNANCE"         = "Entra_ID_Governance"
    "Entra_Identity_Governance"         = "Entra_ID_Governance"
    # Nuevos nombres Entra (rebrand Azure AD -> Entra ID)
    "ENTRA_ID_P1"                       = "Entra_ID_P1"
    "ENTRA_ID_P2"                       = "Entra_ID_P2"
    "ENTRA_ID_GOVERNANCE"               = "Entra_ID_Governance"
    # AAD_SMB = "Azure Active Directory" basico para Business SKUs (Basic, Standard).
    # NO es Entra P1 real (sin Conditional Access, sin Identity Protection).
    # Business Premium obtiene P1 via AAD_PREMIUM por separado. Excluido.

    # --- Defender for Endpoint (MDE) ---
    "WINDEFATP"                         = "MDE_P2"
    "MDATP_XPLAT"                       = "MDE_P2"
    "MDATP_SERVER"                      = "MDE_P2"   # MDE for Servers (Defender for Servers add-on)
    "DEFENDER_ENDPOINT_P1"              = "MDE_P1"
    "MDE_LITE"                          = "MDE_P1"
    "MDE_SMB"                           = "MDE_P1"
    "DEFENDER_FOR_BUSINESS_PROTECTION"  = "MDE_P1"   # Microsoft Defender for Business plan name variant
    "MDE_ENDPOINT_DETECTION_AND_RESPONSE" = "MDE_P2"
    "MDE_P2_DEVICE"                     = "MDE_P2"
    # Variantes GCC / nombres nuevos
    "WINDEFATP_GOV"                     = "MDE_P2"    # GCC variant
    "DEFENDER_ENDPOINT_P1_GOV"          = "MDE_P1"    # GCC variant
    "MICROSOFT_DEFENDER_ENDPOINT"       = "MDE_P2"    # Newer plan name
    "MICROSOFT_DEFENDER_ENDPOINT_P1"    = "MDE_P1"    # Newer plan name
    "MDE_E5"                            = "MDE_P2"    # E5 embedded variant

    # --- Defender for Office 365 (MDO) ---
    # P1: proteccion basica (Safe Attachments, Safe Links)
    "ATP_ENTERPRISE"                    = "MDO_P1"
    "ATP_ENTERPRISE_GOV"                = "MDO_P1"
    "ATP_ENTERPRISE_FACULTY"            = "MDO_P1"
    "ATP_ENTERPRISE_STUDENT"            = "MDO_P1"    # Student/EDU variant
    "OFFICE_365_ADVANCED_THREAT_PROTECTION" = "MDO_P1"
    "SAFEDOCS"                          = "MDO_P1"
    "ATP_MULTI_GEO"                     = "MDO_P1"
    # P2: P1 + investigacion, Threat Explorer, Attack Simulation
    "THREAT_INTELLIGENCE"               = "MDO_P2"
    "THREAT_INTELLIGENCE_GOV"           = "MDO_P2"
    "OFFICE_365_THREAT_INTELLIGENCE"    = "MDO_P2"
    "THREAT_INTELLIGENCE_FACULTY"       = "MDO_P2"
    "THREAT_INTELLIGENCE_STUDENT"       = "MDO_P2"    # Student/EDU variant
    "COMMON_DEFENDER_PLATFORM_FOR_OFFICE" = "MDO_P1"  # Plataforma comun MDO — aparece en SKUs con MDO real

    # --- Defender for Cloud Apps (MDA / MCAS) ---
    "ADALLOM_S_STANDALONE"              = "MDA"
    # ADALLOM_S_O365 = "Office 365 Cloud App Security" (OCAS) — subset de MDA limitado a O365.
    # Solo cubre Exchange/SharePoint/OneDrive/Teams. NO conecta apps de terceros (Box, Salesforce, AWS).
    # NO incluye gobernanza cross-SaaS, custom connectors ni UEBA completo.
    # Viene con O365 E5. MDA full requiere M365 E5 Security, EMS E5 o MDA standalone. Excluido.
    "ADALLOM_S_STANDALONE_GOV"          = "MDA"       # GCC variant
    "CLOUD_APP_SECURITY"                = "MDA"       # Alternative plan name
    # ADALLOM_S_DISCOVERY = "Cloud App Discovery" — feature basico de descubrimiento.
    # Viene con Entra P2, EMS E3, M365 F1. NO es MDA real (sin gobernanza, sin DLP, sin politicas).
    # ADALLOM_FOR_AATP = "App Governance" — companion de MDI. No funciona sin MDA full.
    # Ambos excluidos para no inflar el conteo de MDA.

    # --- Defender for Identity (MDI) ---
    "ATA"                               = "MDI"
    "AZURE_ADVANCED_THREAT_PROTECTION"  = "MDI"
    "ATA_FACULTY"                       = "MDI"
    "ATA_GOV"                           = "MDI"       # GCC variant
    "ATA_STUDENT"                       = "MDI"       # Student/EDU variant

    # --- Intune ---
    "INTUNE_A"                          = "Intune_P1"
    "INTUNE_P1"                         = "Intune_P1"
    "INTUNE_P2"                         = "Intune_P2"
    "INTUNE_EDU"                        = "Intune_P1"
    # INTUNE_O365 = "Mobile Device Management for Office 365" — MDM basico (solo enrollment).
    # NO es Intune P1 real. Viene bundled con O365 E3/E5, no se puede quitar.
    # Mapearlo a Intune_P1 genera falsos positivos de overlap con EMS E3 (que tiene INTUNE_A real).
    # Se excluye del mapeo. Aparecera en UnmappedPlans.csv como referencia.
    "INTUNE_SMBIZ"                      = "Intune_P1" # SMB variant
    "INTUNE_A_GOV"                      = "Intune_P1" # GCC variant

    # --- Purview / Compliance ---
    # AIP (Azure Information Protection) - viene con EMS E3/E5, M365 E5 Compliance, M365 E5 full
    # NO viene con E5 Security
    "RMS_S_PREMIUM"                     = "Purview_AIP_P1"
    "RMS_S_PREMIUM2"                    = "Purview_AIP_P2"
    "RMS_S_PREMIUM_GOV"                 = "Purview_AIP_P1"
    "RMS_S_PREMIUM2_GOV"               = "Purview_AIP_P2"   # GCC variant
    # RMS_S_ENTERPRISE = Azure Rights Management basico (servicio de cifrado subyacente).
    # Se incluye en O365 E1/E3/F1 y otros SKUs que NO tienen AIP P1. NO es lo mismo que AIP P1.
    # AIP P1 real = RMS_S_PREMIUM. Mapeado a categoria separada para no inflar el contador AIP P1.
    "RMS_S_ENTERPRISE"                  = "Purview_RMS_Basic"
    "RMS_S_ENTERPRISE_GOV"              = "Purview_RMS_Basic" # GCC variant
    # MIP (Microsoft Information Protection) - viene con M365 E5 Compliance, M365 E5 full
    # NO viene con E5 Security
    "MIP_S_CLP1"                        = "Purview_MIP_P1"
    "MIP_S_CLP2"                        = "Purview_MIP_P2"
    # MIP_S_EXCHANGE = "Data Loss Prevention" basico de Exchange (transport rules).
    # Viene con E3. NO es Endpoint DLP (E5 Compliance). Mapearlo a Purview_DLP
    # infla el conteo E5 Compliance porque $CategoryGroups lo agrupa bajo "Purview (E5 Compliance)".
    # Un usuario E3 apareceria con capacidad DLP de E5. Excluido.
    "MICROSOFTENDPOINTDLP"              = "Purview_DLP"
    "DLP_ANALYTICS"                     = "Purview_DLP"      # DLP analytics component
    # Audit, eDiscovery, Insider Risk - viene con M365 E5 Compliance, M365 E5 full
    "M365_ADVANCED_AUDITING"            = "Purview_Audit"
    "EQUIVIO_ANALYTICS"                 = "Purview_eDiscovery"
    "PURVIEW_EDISCOVERY"                = "Purview_eDiscovery"  # Newer plan name
    # PREMIUM_ENCRYPTION = Advanced Message Encryption (plan de cifrado de mensajes).
    # NO es eDiscovery. Tiene PrepaidUnits=1,000,000 en tenants E5 como indicador de capacidad.
    # Mapeado a Purview_Encryption para que aparezca en la categoria correcta.
    "PREMIUM_ENCRYPTION"                = "Purview_Encryption"
    "INSIDER_RISK"                      = "Purview_InsiderRisk"
    "INSIDER_RISK_MANAGEMENT"           = "Purview_InsiderRisk"
    "INSIDER_RISK_MANAGEMENT_PREMIUM"   = "Purview_InsiderRisk"   # Premium tier
    "COMMUNICATIONS_COMPLIANCE"         = "Purview_CommCompliance"
    "COMMUNICATIONS_DLP"                = "Purview_CommCompliance"
    "MICROSOFT_COMMUNICATION_COMPLIANCE" = "Purview_CommCompliance"
    # INFO_GOVERNANCE = "Microsoft Information Governance" — retencion basica (org-wide, auto-apply).
    # Viene con E1/E3/F1/F3/Business Basic/Standard/Premium — practicamente todos los SKUs.
    # El plan E5 Compliance exclusivo es RECORDS_MANAGEMENT (ya mapeado). Excluido.
    "RECORDS_MANAGEMENT"                = "Purview_DataLifecycle"
    "INFORMATION_BARRIERS"              = "Purview_InfoBarriers"    # Information Barriers (E5 Compliance)
    # CONTENT_EXPLORER = "Information Protection and Governance Analytics – Standard".
    # Viene con E1/E3/E5/F1/F3/Business Basic — practicamente todos los SKUs.
    # NO es E5 Compliance exclusivo. Mapearlo infla el conteo E5. Excluido.
    # ML_CLASSIFICATION = "Microsoft ML-Based Classification" (clasificadores built-in).
    # Viene con E3/E5/O365 E3. NO es exclusivo de E5 Compliance. Excluido.
    # PURVIEW_DISCOVERY = "eDiscovery Standard" — busqueda de contenido + hold basico.
    # Viene con E3/E5. El plan E5 Premium ya esta cubierto por EQUIVIO_ANALYTICS y PURVIEW_EDISCOVERY.
    # Mapearlo a Purview_eDiscovery infla el conteo E5 con usuarios E3. Excluido.
    "DATA_INVESTIGATIONS"               = "Purview_eDiscovery"
    # M365_AUDIT_PLATFORM = "Microsoft 365 Audit Platform" — plataforma de auditoria BASICA.
    # Viene con E1/E3/E5/Business etc. (retencion 90 dias, sin high-value events).
    # Mapearlo a Purview_Audit infla el conteo E5 Compliance. El plan E5 real es M365_ADVANCED_AUDITING.
    # Excluido.
    "CUSTOMER_KEY"                      = "Purview_Encryption"
    "CustomerLockboxA_Enterprise"       = "Purview_Lockbox"
    "LOCKBOX_ENTERPRISE"                = "Purview_Lockbox"
    "PAM_ENTERPRISE"                    = "Purview_PAM"

    # --- Productividad ---
    "EXCHANGE_S_ENTERPRISE"             = "Exchange_Online"
    "EXCHANGE_S_STANDARD"               = "Exchange_Online"
    # EXCHANGE_S_FOUNDATION = Exchange Foundation — servicio backend minimo, NO es un buzon real.
    # Viene con EMS E3, Entra P2, y otros SKUs que no son de Exchange.
    # Mapearlo a Exchange_Online infla el conteo. Excluido.
    "EXCHANGE_S_DESKLESS"               = "Exchange_Online"   # Exchange Online Kiosk (F1)
    "EXCHANGE_S_ENTERPRISE_GOV"         = "Exchange_Online"   # GCC variant
    "EXCHANGE_S_STANDARD_GOV"           = "Exchange_Online"   # GCC variant
    "SHAREPOINTENTERPRISE"              = "SharePoint"
    "SHAREPOINTWAC"                     = "SharePoint"
    "SHAREPOINTSTANDARD"                = "SharePoint"
    "SHAREPOINTDESKLESS"                = "SharePoint"        # SharePoint (F1 Kiosk)
    "SHAREPOINTENTERPRISE_GOV"          = "SharePoint"        # GCC variant
    "SHAREPOINTWAC_GOV"                 = "SharePoint"        # GCC variant
    "TEAMS1"                            = "Teams"
    "TEAMS_GOV"                         = "Teams"
    "TEAMS_AR_GCCHIGH"                  = "Teams"             # GCC-High variant
    "MCOSTANDARD"                       = "Teams"
    "MCOSTANDARD_GOV"                   = "Teams"             # GCC variant
    "MCOEV"                             = "Teams"
    "OFFICESUBSCRIPTION"                = "M365_Apps"
    "OFFICE_PROPLUS_DEVICE"             = "M365_Apps"
    "OFFICEMOBILE_SUBSCRIPTION"         = "M365_Apps"         # Office Mobile (F3)
    "OFFICESUBSCRIPTION_GOV"            = "M365_Apps"         # GCC variant
    "BI_AZURE_P2"                       = "PowerBI_Pro"
    "BI_AZURE_P_2_GOV"                  = "PowerBI_Pro"
    "POWER_APPS_P2"                     = "PowerApps"
    "FLOW_P2"                           = "PowerAutomate"
    "POWERAPPS_O365_P1"                 = "PowerApps"         # PowerApps for O365 E1
    "POWERAPPS_O365_P2"                 = "PowerApps"         # PowerApps for O365 E3
    "POWERAPPS_O365_P3"                 = "PowerApps"
    "FLOW_O365_P1"                      = "PowerAutomate"     # Power Automate for O365 E1
    "FLOW_O365_P2"                      = "PowerAutomate"     # Power Automate for O365 E3
    "FLOW_O365_P3"                      = "PowerAutomate"

    # --- Copilot ---
    "MICROSOFT_COPILOT_O365"            = "Copilot_M365"
    "M365_COPILOT"                      = "Copilot_M365"
}

# Categorias clave que queremos en el reporte de adoption
# NOTA sobre licenciamiento:
#   E5 Security  = Entra P2 + MDE P2 + MDO P2 + MDA + MDI (NO incluye Purview/AIP)
#   E5 Compliance = AIP P1/P2 + MIP P1/P2 + DLP + Audit + eDiscovery + Insider Risk (NO incluye Security)
#   M365 E5 full  = Security + Compliance + Productividad
#   EMS E3        = Entra P1 + AIP P1 + Intune P1
#   EMS E5        = Entra P2 + AIP P2 + MDA + MDI + Intune P1
$SecurityCategories = @(
    "Entra_ID_P1", "Entra_ID_P2", "Entra_ID_Governance",
    "MDE_P1", "MDE_P2",
    "MDO_P1", "MDO_P2",
    "MDA", "MDI",
    "Intune_P1", "Intune_P2",
    "Purview_AIP_P1", "Purview_AIP_P2",
    "Purview_MIP_P1", "Purview_MIP_P2",
    "Purview_DLP",
    "Purview_Audit", "Purview_eDiscovery",
    "Purview_InsiderRisk", "Purview_CommCompliance", "Purview_DataLifecycle",
    "Purview_Encryption", "Purview_Lockbox", "Purview_PAM",
    "Purview_InfoBarriers",
    "Copilot_M365"
)

$AllCategories = $SecurityCategories + @(
    "Exchange_Online", "SharePoint", "Teams", "M365_Apps",
    "PowerBI_Pro", "PowerApps", "PowerAutomate"
)

# Agrupacion para el reporte - separado por licenciamiento real
$CategoryGroups = [ordered]@{
    "Identidad (Entra ID)"            = @("Entra_ID_P1", "Entra_ID_P2", "Entra_ID_Governance")
    "Endpoint (MDE)"                  = @("MDE_P1", "MDE_P2")
    "Email Security (MDO)"            = @("MDO_P1", "MDO_P2")
    "Cloud Apps (MDA)"                = @("MDA")
    "Identity Threat (MDI)"           = @("MDI")
    "Device Mgmt (Intune)"            = @("Intune_P1", "Intune_P2")
    "Info Protection (EMS/Compliance)" = @("Purview_AIP_P1", "Purview_AIP_P2", "Purview_MIP_P1", "Purview_MIP_P2")
    "Purview (E5 Compliance)"         = @("Purview_DLP", "Purview_Audit", "Purview_eDiscovery", "Purview_InsiderRisk", "Purview_CommCompliance", "Purview_DataLifecycle", "Purview_Encryption", "Purview_Lockbox", "Purview_PAM", "Purview_InfoBarriers")
    "Productividad"                   = @("Exchange_Online", "SharePoint", "Teams", "M365_Apps")
    "AI / Analytics"                  = @("Copilot_M365", "PowerBI_Pro", "PowerApps", "PowerAutomate")
}

# SKU friendly names
$SkuFriendlyNames = @{
    "SPE_E3"                                     = "Microsoft 365 E3"
    "SPE_E5"                                     = "Microsoft 365 E5"
    "SPE_E5_NOPSTNCONF"                          = "Microsoft 365 E5 (sin Audio)"
    "SPE_E5_CALLINGMINUTES"                       = "Microsoft 365 E5 (con minutos)"
    "ENTERPRISEPACK"                             = "Office 365 E3"
    "ENTERPRISEPREMIUM"                          = "Office 365 E5"
    "ENTERPRISEPREMIUM_NOPSTNCONF"               = "Office 365 E5 (sin Audio)"
    "DEVELOPERPACK_E5"                           = "Microsoft 365 E5 Developer"
    "M365_F1"                                    = "Microsoft 365 F1"
    "SPE_F1"                                     = "Microsoft 365 F3"
    "SPB"                                        = "Microsoft 365 Business Premium"
    "O365_BUSINESS_PREMIUM"                      = "Microsoft 365 Business Standard"
    "SMB_BUSINESS"                               = "Microsoft 365 Apps for Business"
    "SMB_BUSINESS_ESSENTIALS"                    = "Microsoft 365 Business Basic"
    "IDENTITY_THREAT_PROTECTION"                 = "Microsoft 365 E5 Security"
    "IDENTITY_THREAT_PROTECTION_FOR_EMS_E3"      = "Microsoft 365 E5 Security (EMS E3)"
    "INFORMATION_PROTECTION_COMPLIANCE"          = "Microsoft 365 E5 Compliance"
    "EMS"                                        = "Enterprise Mobility + Security E3"
    "EMSPREMIUM"                                 = "Enterprise Mobility + Security E5"
    "AAD_PREMIUM"                                = "Azure AD Premium P1"
    "AAD_PREMIUM_P2"                             = "Azure AD Premium P2"
    "ATA"                                        = "Defender for Identity"
    "ATP_ENTERPRISE"                             = "Defender for Office 365 P1"
    "THREAT_INTELLIGENCE"                        = "Defender for Office 365 P2"
    "MDATP_XPLAT"                                = "Defender for Endpoint P2"
    "WIN_DEF_ATP"                                = "Defender for Endpoint P1"
    "MCAS"                                       = "Defender for Cloud Apps"
    "INTUNE_A"                                   = "Microsoft Intune Plan 1"
    "INTUNE_A_D"                                 = "Microsoft Intune Plan 2"
    "Microsoft_Intune_Suite"                     = "Microsoft Intune Suite"
    "RIGHTSMANAGEMENT"                           = "Azure Information Protection P1"
    "RIGHTSMANAGEMENT_ADHOC"                     = "Azure Rights Management"
    "EQUIVIO_ANALYTICS"                          = "Purview eDiscovery Premium"
    "EXCHANGESTANDARD"                           = "Exchange Online Plan 1"
    "EXCHANGEENTERPRISE"                         = "Exchange Online Plan 2"
    "FLOW_FREE"                                  = "Power Automate Free"
    "POWER_BI_STANDARD"                          = "Power BI Free"
    "POWER_BI_PRO"                               = "Power BI Pro"
    "PROJECTPREMIUM"                             = "Project Plan 5"
    "PROJECTPROFESSIONAL"                        = "Project Plan 3"
    "VISIOCLIENT"                                = "Visio Plan 2"
    "STREAM"                                     = "Microsoft Stream"
    "TEAMS_EXPLORATORY"                          = "Teams Exploratory"
    "TEAMS_PREMIUM"                              = "Teams Premium"
    "Microsoft_Teams_Audio_Conferencing_select_dial_out" = "Teams Audio Conferencing"
    "Microsoft_365_Copilot"                      = "Microsoft 365 Copilot"
    "SECURITY_COPILOT"                           = "Security Copilot"
    "STANDARDPACK"                               = "Office 365 E1"
    "DESKLESSPACK"                               = "Office 365 F3"
    "OFFICESUBSCRIPTION"                         = "Microsoft 365 Apps for Enterprise"
    "DEFENDER_ENDPOINT_P1"                       = "Defender for Endpoint P1"
    "O365_BUSINESS_ESSENTIALS"                   = "Microsoft 365 Business Basic"
    "DEFENDER_FOR_BUSINESS"                      = "Microsoft Defender for Business"

    # --- Frontline Workers (F-series) ---
    "M365_F1_COMM"                               = "Microsoft 365 F1"
    "SPE_F3"                                     = "Microsoft 365 F3"
    "M365_F5_SECURITY"                           = "Microsoft 365 F5 Security"
    "M365_F5_SEC"                                = "Microsoft 365 F5 Security"
    "DefenderSuite_FLW"                          = "Microsoft 365 F5 Security (Defender Suite FLW)"
    "M365_F5_COMPLIANCE"                         = "Microsoft 365 F5 Compliance"
    "M365_F5_COMP"                               = "Microsoft 365 F5 Compliance"
    "PurviewSuite_FLW"                           = "Microsoft 365 F5 Compliance (Purview Suite FLW)"
    "M365_F5_SEC_COMP"                           = "Microsoft 365 F5 Security + Compliance"
    "DefenderPurviewSuite_FLW"                   = "Microsoft 365 F5 Security + Compliance (FLW)"

    # --- E3/E5 Government & Education ---
    "SPE_E3_GOV"                                 = "Microsoft 365 E3 (GCC)"
    "SPE_E5_GOV"                                 = "Microsoft 365 E5 (GCC)"
    "ENTERPRISEPACK_GOV"                         = "Office 365 E3 (GCC)"
    "ENTERPRISEPREMIUM_GOV"                      = "Office 365 E5 (GCC)"
    "M365EDU_A3_FACULTY"                         = "Microsoft 365 A3 Faculty"
    "M365EDU_A3_STUDENT"                         = "Microsoft 365 A3 Student"
    "M365EDU_A5_FACULTY"                         = "Microsoft 365 A5 Faculty"
    "M365EDU_A5_STUDENT"                         = "Microsoft 365 A5 Student"

    # --- Entra / Identity add-ons ---
    "MICROSOFT_ENTRA_PRIVATE_ACCESS_FOR_FLW"     = "Microsoft Entra Private Access (FLW)"
    "Microsoft_Entra_ID_Governance_Step_Up_for_Microsoft_Entra_ID_P2" = "Entra ID Governance Step-Up"
    "ENTRA_ID_P1"                                = "Microsoft Entra ID P1"
    "ENTRA_ID_P2"                                = "Microsoft Entra ID P2"
    "ENTRA_ID_GOVERNANCE"                        = "Microsoft Entra ID Governance"

    # --- Defender standalone SKUs ---
    "MDATP_Server"                               = "Defender for Endpoint for Servers"
}

# ============================================================================
# FUNCIONES
# ============================================================================
function Get-FriendlySkuName {
    param([string]$SkuPartNumber)
    if ($SkuFriendlyNames.ContainsKey($SkuPartNumber)) {
        return $SkuFriendlyNames[$SkuPartNumber]
    }
    return $SkuPartNumber
}

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

# ============================================================================
# INICIO
# ============================================================================
$ScriptStart = Get-Date

Write-Host ""
Write-Host "  Microsoft 365 Licensing Assessment" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$InactiveDate = (Get-Date).AddDays(-$InactiveDays)

# ============================================================================
# FASE 1: CONEXION
# ============================================================================
Write-Section "Fase 1: Conexion a Microsoft Graph"

$Scopes = @(
    "Directory.Read.All",
    "Organization.Read.All",
    "User.Read.All",
    "AuditLog.Read.All"
)

try {
    # Reusar sesion existente si el orquestador ya conecto
    $PreExistingSession = $false
    try { $ExistingCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { $ExistingCtx = $null }
    if ($ExistingCtx -and $ExistingCtx.Account) {
        $PreExistingSession = $true
        $Context = $ExistingCtx
        Write-OK "Reusando sesion existente: $($Context.Account)"
    } else {
        $ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true }
        if ($TenantId) { $ConnectParams.TenantId = $TenantId }
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
# FASE 2: TENANT + SKUs + REGISTRO DINAMICO DE SERVICE PLANS
# ============================================================================
Write-Section "Fase 2: Inventario de SKUs y Service Plans"

# Tenant info
Write-Step "Obteniendo info del tenant..."
$TenantName  = "Unknown"
$TenantDomain = "Unknown"
$OrgId = $Context.TenantId

for ($retry = 1; $retry -le 3; $retry++) {
    try {
        $Org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        if ($Org) {
            $TenantName   = $Org.DisplayName
            $TenantDomain = ($Org.VerifiedDomains | Where-Object { $_.IsDefault } | Select-Object -First 1).Name
            $OrgId        = $Org.Id
        }
        break
    } catch {
        if ($retry -lt 3) {
            Write-Step "Timeout obteniendo org, reintentando ($retry/3)..."
            Start-Sleep -Seconds 5
        } else {
            Write-Warn "No se pudo obtener info de la org. Usando datos del contexto."
            $TenantName  = $Context.TenantId
            $TenantDomain = $Context.Account -replace ".*@", ""
        }
    }
}
Write-OK "Tenant: $TenantName ($TenantDomain)"

# SKUs
Write-Step "Obteniendo SKUs suscritos..."
$SubscribedSkus = $null
for ($retry = 1; $retry -le 3; $retry++) {
    try {
        $SubscribedSkus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
        break
    } catch {
        if ($retry -lt 3) {
            Write-Step "Timeout obteniendo SKUs, reintentando ($retry/3)..."
            Start-Sleep -Seconds 5
        } else {
            Write-Warn "No se pudo obtener SKUs despues de 3 intentos: $_"
            exit 1
        }
    }
}
Write-OK "$($SubscribedSkus.Count) SKUs encontrados"

# Construir registro dinamico: ServicePlanId -> { Name, Category }
# y SkuId -> [Categories incluidas]
Write-Step "Construyendo registro de service plans desde los SKUs del tenant..."

$PlanRegistry = @{}       # ServicePlanId -> @{ Name; Category }
$SkuCategories = @{}      # SkuId -> @( category1, category2, ... )
$SkuPlanDetails = @{}     # SkuId -> @( @{PlanId; PlanName; Category}, ... )

foreach ($Sku in $SubscribedSkus) {
    $CategoriesInSku = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($Plan in $Sku.ServicePlans) {
        $PlanId   = $Plan.ServicePlanId.ToString()
        $PlanName = $Plan.ServicePlanName

        # Clasificar por nombre
        $Category = $null
        if ($PlanNameToCategory.ContainsKey($PlanName)) {
            $Category = $PlanNameToCategory[$PlanName]
        }

        if (-not $PlanRegistry.ContainsKey($PlanId)) {
            $PlanRegistry[$PlanId] = @{
                Name     = $PlanName
                Category = $Category
            }
        }

        if ($Category) {
            [void]$CategoriesInSku.Add($Category)
        }

        # Detalle por SKU
        if (-not $SkuPlanDetails.ContainsKey($Sku.SkuId.ToString())) {
            $SkuPlanDetails[$Sku.SkuId.ToString()] = [System.Collections.Generic.List[object]]::new()
        }
        $SkuPlanDetails[$Sku.SkuId.ToString()].Add(@{
            PlanId   = $PlanId
            PlanName = $PlanName
            Category = $Category
        })
    }

    $SkuCategories[$Sku.SkuId.ToString()] = @($CategoriesInSku)
}

# SKUs gratuitos/libres: PrepaidUnits >= 10,000 (ej: Power BI Free, Flow Free, Teams Exploratory)
# Estos SKUs incluyen service plans vestigiales (como EQUIVIO_ANALYTICS) que no representan
# funcionalidad real. Se excluyen del analisis de overlap para evitar falsos positivos.
$FreeSkuIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($Sku in $SubscribedSkus) {
    if ($Sku.PrepaidUnits.Enabled -ge 10000) {
        [void]$FreeSkuIds.Add($Sku.SkuId.ToString())
    }
}
if ($FreeSkuIds.Count -gt 0) {
    $FreeNames = foreach ($fid in $FreeSkuIds) { ($SubscribedSkus | Where-Object { $_.SkuId.ToString() -eq $fid } | Select-Object -First 1).SkuPartNumber }
    Write-Step "SKUs gratuitos excluidos de overlap: $($FreeNames -join ', ')"
}

# Hashtable de lookup rapido: SkuId -> FriendlyName (evita Where-Object en loop de usuarios)
$SkuIdToFriendlyName = @{}
$SkuIdToPartNumber   = @{}
foreach ($Sku in $SubscribedSkus) {
    $Sid = $Sku.SkuId.ToString()
    $SkuIdToFriendlyName[$Sid] = Get-FriendlySkuName -SkuPartNumber $Sku.SkuPartNumber
    $SkuIdToPartNumber[$Sid]   = $Sku.SkuPartNumber
}

$MappedPlans   = @($PlanRegistry.Values | Where-Object { $_.Category }).Count
$UnmappedPlans = @($PlanRegistry.Values | Where-Object { -not $_.Category }).Count
Write-OK "$($PlanRegistry.Count) service plans registrados ($MappedPlans clasificados, $UnmappedPlans sin clasificar)"

# Diagnostico: mostrar planes sin clasificar (ayuda a detectar MDO u otros con nombres nuevos)
$UnmappedList = $PlanRegistry.Values | Where-Object { -not $_.Category } | ForEach-Object { $_.Name } | Sort-Object -Unique
if ($UnmappedList) {
    Write-Host "`n  Service Plans sin clasificar encontrados en el tenant:" -ForegroundColor DarkYellow
    foreach ($PlanName in $UnmappedList) {
        Write-Host "    - $PlanName" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Exportar lista completa para revision
    $UnmappedCsvPath = Join-Path $OutputPath "${Timestamp}_00_UnmappedPlans.csv"
    $UnmappedList | ForEach-Object { [PSCustomObject]@{ ServicePlanName = $_ } } |
        Export-Csv -Path $UnmappedCsvPath -NoTypeInformation -Encoding UTF8
    Write-OK "Planes sin clasificar exportados: $UnmappedCsvPath"
}

# Resumen de SKUs
$SkuSummary = [System.Collections.Generic.List[object]]::new()

foreach ($Sku in $SubscribedSkus) {
    $FriendlyName = Get-FriendlySkuName -SkuPartNumber $Sku.SkuPartNumber
    $Available    = $Sku.PrepaidUnits.Enabled
    $Assigned     = $Sku.ConsumedUnits
    $Suspended    = $Sku.PrepaidUnits.Suspended
    $Warning      = $Sku.PrepaidUnits.Warning
    $Unassigned   = $Available - $Assigned
    $PctUsed      = if ($Available -gt 0) { [math]::Round(($Assigned / $Available) * 100, 1) } else { 0 }

    $SkuObj = [PSCustomObject]@{
        SKU_ID              = $Sku.SkuId
        SKU_PartNumber      = $Sku.SkuPartNumber
        FriendlyName        = $FriendlyName
        Total               = $Available
        Assigned            = $Assigned
        Unassigned          = $Unassigned
        Suspended           = $Suspended
        Warning             = $Warning
        PctUsed             = $PctUsed
        IncludedCategories  = ($SkuCategories[$Sku.SkuId.ToString()] -join " | ")
    }
    $SkuSummary.Add($SkuObj)

    # Color en consola
    $Color = if ($Unassigned -lt 0) { "Red" } elseif ($PctUsed -gt 90) { "Yellow" } else { "White" }
    Write-Host "  $FriendlyName" -ForegroundColor $Color
    Write-Host "    Total: $Available | Asignadas: $Assigned | Libres: $Unassigned ($PctUsed%)" -ForegroundColor Gray
}

# Exportar SKUs
$SkuCsvPath = Join-Path $OutputPath "${Timestamp}_01_SKUs.csv"
$SkuSummary | Export-Csv -Path $SkuCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "SKUs exportados: $SkuCsvPath"

# ============================================================================
# FASE 3: ANALISIS DE USUARIOS
# ============================================================================
Write-Section "Fase 3: Analisis de usuarios"

# Obtener conteo total de usuarios del tenant (licenciados + sin licencia)
Write-Step "Obteniendo conteo total de usuarios del tenant..."
$TotalTenantUsers = 0
$TotalMembers = 0
$TotalGuests = 0
try {
    @(Get-MgUser -All:$false -Top 1 -CountVariable TenantCount -ConsistencyLevel eventual -ErrorAction Stop) | Out-Null
    $TotalTenantUsers = $TenantCount

    # Desglose Members vs Guests
    try {
        @(Get-MgUser -All:$false -Top 1 -Filter "userType eq 'Member'" -CountVariable MemberCount -ConsistencyLevel eventual -ErrorAction Stop) | Out-Null
        $TotalMembers = $MemberCount
        $TotalGuests = $TotalTenantUsers - $TotalMembers
    } catch {
        Write-Warn "No se pudo desglosar Members/Guests: $_"
        $TotalMembers = $TotalTenantUsers
        $TotalGuests = 0
    }

    Write-OK "Total de usuarios en el tenant: $($TotalTenantUsers.ToString('N0')) ($($TotalMembers.ToString('N0')) miembros, $($TotalGuests.ToString('N0')) invitados)"
} catch {
    Write-Warn "No se pudo obtener conteo total de usuarios: $_"
}

Write-Step "Obteniendo usuarios con licencias (puede tardar en tenants grandes)..."

$BaseProperties = @(
    "Id", "DisplayName", "UserPrincipalName", "AccountEnabled",
    "Department", "JobTitle", "UsageLocation", "UserType",
    "AssignedLicenses", "AssignedPlans", "LicenseAssignmentStates"
)

$HasSignInActivity = $true
$AllUsers = $null

# Intentar primero con SignInActivity (requiere AAD P1 + AuditLog.Read.All)
Write-Step "Intentando obtener usuarios con SignInActivity..."
for ($retry = 1; $retry -le 3; $retry++) {
    try {
        $AllUsers = @(Get-MgUser -All `
            -Property ($BaseProperties + @("SignInActivity")) `
            -Filter "assignedLicenses/`$count ne 0" `
            -CountVariable LicCount `
            -ConsistencyLevel eventual `
            -PageSize 999 `
            -ErrorAction Stop)
        break
    } catch {
        $ErrMsg = $_.Exception.Message
        # Si es error de permisos/tenant, reintentar sin SignInActivity
        if ($ErrMsg -match "403|Forbidden|b2c|AuditLog|SignInActivity|Authorization") {
            Write-Warn "SignInActivity no disponible en este tenant (requiere AAD P1 + AuditLog.Read.All)"
            Write-Step "Reintentando sin SignInActivity..."
            $HasSignInActivity = $false
            $AllUsers = $null
            break
        }
        if ($retry -lt 3) {
            Write-Step "Timeout obteniendo usuarios, reintentando ($retry/3)..."
            Start-Sleep -Seconds 10
        } else {
            Write-Warn "No se pudo obtener usuarios despues de 3 intentos: $_"
            exit 1
        }
    }
}

# Fallback sin SignInActivity
if (-not $AllUsers) {
    for ($retry = 1; $retry -le 3; $retry++) {
        try {
            $AllUsers = @(Get-MgUser -All `
                -Property $BaseProperties `
                -Filter "assignedLicenses/`$count ne 0" `
                -CountVariable LicCount `
                -ConsistencyLevel eventual `
                -PageSize 999 `
                -ErrorAction Stop)
            break
        } catch {
            if ($retry -lt 3) {
                Write-Step "Timeout obteniendo usuarios, reintentando ($retry/3)..."
                Start-Sleep -Seconds 10
            } else {
                Write-Warn "No se pudo obtener usuarios despues de 3 intentos: $_"
                exit 1
            }
        }
    }
}

if (-not $HasSignInActivity) {
    Write-Warn "Los datos de ultimo sign-in no estaran disponibles en este reporte"
}
Write-OK "$($AllUsers.Count) usuarios con licencias encontrados"

# Listas optimizadas
$UserReport       = [System.Collections.Generic.List[object]]::new()
$DuplicateReport  = [System.Collections.Generic.List[object]]::new()
$WasteReport      = [System.Collections.Generic.List[object]]::new()

# Contadores de adoption
$AdoptionEnabled  = @{}   # category -> count users con plan activo
$AdoptionDisabled = @{}   # category -> count users con plan deshabilitado por admin
foreach ($Cat in $AllCategories) {
    $AdoptionEnabled[$Cat]  = 0
    $AdoptionDisabled[$Cat] = 0
}

# Contadores de waste
$WasteDisabledAccounts   = 0
$WasteInactiveUsers      = 0
$WasteDuplicateLicenses  = 0
$WasteDisabledPlans      = 0

# Contadores de assignment methods (calculados en-loop, no con Where-Object)
$GroupAssigned  = 0
$DirectAssigned = 0
$MixedAssigned  = 0

# Pre-agregar stats por departamento durante el loop de usuarios
$DeptStats = @{}  # dept -> @{ Count; SkuCounts = @{}; CatCounts = @{} }

Write-Step "Procesando usuarios..."
$i = 0
$ProcessStart = Get-Date

foreach ($User in $AllUsers) {
    $i++
    if ($i % 500 -eq 0 -or $i -eq $AllUsers.Count) {
        $Elapsed = ((Get-Date) - $ProcessStart).TotalSeconds
        $Rate = if ($Elapsed -gt 0) { [math]::Round($i / $Elapsed) } else { 0 }
        Write-Host "`r  [*]   $i / $($AllUsers.Count) usuarios procesados ($Rate/s)..." -ForegroundColor Yellow -NoNewline
    }

    # --- Sign-in activity ---
    $LastInteractive    = $User.SignInActivity.LastSignInDateTime
    $LastNonInteractive = $User.SignInActivity.LastNonInteractiveSignInDateTime

    # Usar el mas reciente entre interactivo y no-interactivo
    $LastSignIn = $null
    if ($LastInteractive -and $LastNonInteractive) {
        $LastSignIn = @($LastInteractive, $LastNonInteractive) | Sort-Object -Descending | Select-Object -First 1
    } elseif ($LastInteractive) {
        $LastSignIn = $LastInteractive
    } elseif ($LastNonInteractive) {
        $LastSignIn = $LastNonInteractive
    }

    $DaysSinceSignIn = if ($LastSignIn) {
        [math]::Round(((Get-Date) - [datetime]$LastSignIn).TotalDays, 0)
    } else { -1 }  # -1 = nunca

    $IsInactive = ($DaysSinceSignIn -gt $InactiveDays) -or ($DaysSinceSignIn -eq -1)

    # --- Planes activos (del usuario, ya consolidados por Graph) ---
    $EnabledPlanIds = [System.Collections.Generic.HashSet[string]]::new()
    if ($User.AssignedPlans) {
        foreach ($Plan in $User.AssignedPlans) {
            if ($Plan.CapabilityStatus -eq "Enabled") {
                [void]$EnabledPlanIds.Add($Plan.ServicePlanId.ToString())
            }
        }
    }

    # Categorias activas del usuario
    $UserEnabledCategories = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($PlanId in $EnabledPlanIds) {
        if ($PlanRegistry.ContainsKey($PlanId) -and $PlanRegistry[$PlanId].Category) {
            [void]$UserEnabledCategories.Add($PlanRegistry[$PlanId].Category)
        }
    }

    # --- SKUs asignados (mover antes de disabled para poder derivar categorias) ---
    $UserSkuNames = [System.Collections.Generic.List[string]]::new()
    $UserSkuIds   = [System.Collections.Generic.List[string]]::new()
    if ($User.AssignedLicenses) {
        foreach ($License in $User.AssignedLicenses) {
            $Sid = $License.SkuId.ToString()
            $UserSkuIds.Add($Sid)
            if ($SkuIdToFriendlyName.ContainsKey($Sid)) {
                $UserSkuNames.Add($SkuIdToFriendlyName[$Sid])
            }
        }
    }

    # --- Categorias deshabilitadas: SKU provee la categoria pero no esta habilitada ---
    # Derivar de lo que los SKUs del usuario deberian proveer vs lo que realmente tiene activo.
    # Esto captura: planes deshabilitados por admin, cuentas suspendidas, y cualquier estado no-Enabled.
    $UserDisabledCategories = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Sid in $UserSkuIds) {
        if ($SkuCategories.ContainsKey($Sid)) {
            foreach ($Cat in $SkuCategories[$Sid]) {
                if (-not $UserEnabledCategories.Contains($Cat)) {
                    [void]$UserDisabledCategories.Add($Cat)
                }
            }
        }
    }

    # --- Asignacion grupo vs directa ---
    $AssignmentMethod = "Direct"
    if ($User.LicenseAssignmentStates) {
        $HasGroup  = $User.LicenseAssignmentStates | Where-Object { $_.AssignedByGroup }
        $HasDirect = $User.LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup }
        if ($HasGroup -and $HasDirect) {
            $AssignmentMethod = "Group+Direct"
        } elseif ($HasGroup) {
            $AssignmentMethod = "Group"
        }
    }

    # --- Deteccion de duplicados ---
    $UserDuplicates = [System.Collections.Generic.List[string]]::new()
    if ($UserSkuIds.Count -gt 1) {
        # Contar cuantos SKUs de PAGO proveen cada categoria (excluir SKUs gratuitos)
        $CategoryProviders = @{}
        foreach ($Sid in $UserSkuIds) {
            if ($FreeSkuIds.Contains($Sid)) { continue }  # Ignorar SKUs gratuitos
            if ($SkuCategories.ContainsKey($Sid)) {
                foreach ($Cat in $SkuCategories[$Sid]) {
                    if ($SecurityCategories -contains $Cat) {
                        if (-not $CategoryProviders.ContainsKey($Cat)) {
                            $CategoryProviders[$Cat] = [System.Collections.Generic.List[string]]::new()
                        }
                        $CategoryProviders[$Cat].Add($Sid)
                    }
                }
            }
        }
        foreach ($Cat in $CategoryProviders.Keys) {
            if ($CategoryProviders[$Cat].Count -gt 1) {
                $UserDuplicates.Add($Cat)
                $ProviderNames = $CategoryProviders[$Cat] | ForEach-Object {
                    if ($SkuIdToFriendlyName.ContainsKey($_)) { $SkuIdToFriendlyName[$_] } else { $_ }
                }
                $DuplicateReport.Add([PSCustomObject]@{
                    UPN               = $User.UserPrincipalName
                    DisplayName       = $User.DisplayName
                    DuplicateProduct  = $Cat
                    ProvidedBySKUs    = ($ProviderNames -join " | ")
                })
            }
        }
    }

    # --- Clasificacion de waste ---
    $WasteReasons = [System.Collections.Generic.List[string]]::new()
    if (-not $User.AccountEnabled) {
        $WasteReasons.Add("Account_Disabled")
        $WasteDisabledAccounts++
    }
    if ($IsInactive -and $User.AccountEnabled) {
        $WasteReasons.Add("Inactive_${InactiveDays}d")
        $WasteInactiveUsers++
    }
    if ($UserDuplicates.Count -gt 0) {
        $WasteReasons.Add("SKU_Overlap")
        $WasteDuplicateLicenses++
    }

    # Detectar usuarios con SKU de pago pero mayoria de planes de seguridad deshabilitados
    $HasPaidSku = $UserSkuIds | Where-Object {
        $sid = $_
        $sku = $SubscribedSkus | Where-Object { $_.SkuId.ToString() -eq $sid }
        $sku -and $sku.PrepaidUnits.Enabled -gt 0 -and $sku.PrepaidUnits.Enabled -lt 10000
    }
    if ($HasPaidSku -and $UserDisabledCategories.Count -gt 0) {
        $TotalSecPlans = $UserEnabledCategories.Count + $UserDisabledCategories.Count
        if ($TotalSecPlans -gt 0 -and ($UserDisabledCategories.Count / $TotalSecPlans) -ge 0.5) {
            $WasteReasons.Add("DisabledPlans_$($UserDisabledCategories.Count)of$($TotalSecPlans)")
            $WasteDisabledPlans++
        }
    }

    if ($WasteReasons.Count -gt 0) {
        $WasteReport.Add([PSCustomObject]@{
            UPN           = $User.UserPrincipalName
            DisplayName   = $User.DisplayName
            AccountEnabled = $User.AccountEnabled
            LastSignIn    = if ($LastSignIn) { ([datetime]$LastSignIn).ToString("yyyy-MM-dd") } else { "Nunca" }
            DaysSinceSignIn = if ($DaysSinceSignIn -ge 0) { $DaysSinceSignIn } else { "N/A" }
            AssignedSKUs  = ($UserSkuNames -join " | ")
            WasteReasons  = ($WasteReasons -join " | ")
        })
    }

    # --- Contadores de adoption ---
    foreach ($Cat in $AllCategories) {
        if ($UserEnabledCategories.Contains($Cat)) {
            $AdoptionEnabled[$Cat]++
        } elseif ($UserDisabledCategories.Contains($Cat)) {
            $AdoptionDisabled[$Cat]++
        }
    }

    # --- Conditional Access: disponible si tiene Entra P1 o P2 ---
    $HasCA = $UserEnabledCategories.Contains("Entra_ID_P1") -or $UserEnabledCategories.Contains("Entra_ID_P2")

    # --- Construir objeto del usuario ---
    $UserObj = [PSCustomObject]@{
        DisplayName         = $User.DisplayName
        UPN                 = $User.UserPrincipalName
        AccountEnabled      = $User.AccountEnabled
        UserType            = $User.UserType
        Department          = $User.Department
        JobTitle            = $User.JobTitle
        UsageLocation       = $User.UsageLocation
        AssignedSKUs        = ($UserSkuNames -join " | ")
        AssignmentMethod    = $AssignmentMethod
        HasConditionalAccess = $HasCA
        LastSignIn          = if ($LastSignIn) { ([datetime]$LastSignIn).ToString("yyyy-MM-dd") } else { "Nunca" }
        DaysSinceSignIn     = if ($DaysSinceSignIn -ge 0) { $DaysSinceSignIn } else { "N/A" }
        IsInactive          = $IsInactive
        DisabledPlans       = ($UserDisabledCategories -join " | ")
        DuplicatePlans      = ($UserDuplicates -join " | ")
        WasteFlags          = ($WasteReasons -join " | ")
    }

    # Agregar columna por cada categoria clave
    foreach ($Cat in $SecurityCategories) {
        $Value = if ($UserEnabledCategories.Contains($Cat)) { "Enabled" }
                 elseif ($UserDisabledCategories.Contains($Cat)) { "Disabled" }
                 else { "" }
        $UserObj | Add-Member -NotePropertyName $Cat -NotePropertyValue $Value
    }

    # --- Contar assignment methods in-loop (evita 3 Where-Object separados) ---
    switch ($AssignmentMethod) {
        "Group"        { $GroupAssigned++ }
        "Group+Direct" { $MixedAssigned++ }
        default        { $DirectAssigned++ }
    }

    # --- Agregar stats de departamento in-loop (evita O(depts * cats * users)) ---
    $DeptKey = if ($User.Department) { $User.Department } else { "(Sin departamento)" }
    if (-not $DeptStats.ContainsKey($DeptKey)) {
        $DeptStats[$DeptKey] = @{ Count = 0; SkuCounts = @{}; CatCounts = @{} }
    }
    $DeptStats[$DeptKey].Count++
    foreach ($SkuName in $UserSkuNames) {
        if (-not $DeptStats[$DeptKey].SkuCounts.ContainsKey($SkuName)) { $DeptStats[$DeptKey].SkuCounts[$SkuName] = 0 }
        $DeptStats[$DeptKey].SkuCounts[$SkuName]++
    }
    foreach ($Cat in $SecurityCategories) {
        if ($UserEnabledCategories.Contains($Cat)) {
            if (-not $DeptStats[$DeptKey].CatCounts.ContainsKey($Cat)) { $DeptStats[$DeptKey].CatCounts[$Cat] = 0 }
            $DeptStats[$DeptKey].CatCounts[$Cat]++
        }
    }

    $UserReport.Add($UserObj)
}
Write-Host ""  # nueva linea tras progreso inline

Write-OK "$($AllUsers.Count) usuarios procesados"

# Exportar CSVs
$UserCsvPath = Join-Path $OutputPath "${Timestamp}_02_Users.csv"
$UserReport | Export-Csv -Path $UserCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "Usuarios: $UserCsvPath"

if ($WasteReport.Count -gt 0) {
    $WasteCsvPath = Join-Path $OutputPath "${Timestamp}_04_Waste.csv"
    $WasteReport | Export-Csv -Path $WasteCsvPath -NoTypeInformation -Encoding UTF8
    Write-OK "Desperdicio: $WasteCsvPath"
}

if ($DuplicateReport.Count -gt 0) {
    $DupCsvPath = Join-Path $OutputPath "${Timestamp}_05_Duplicates.csv"
    $DuplicateReport | Export-Csv -Path $DupCsvPath -NoTypeInformation -Encoding UTF8
    Write-OK "Duplicados: $DupCsvPath"
}

# ============================================================================
# FASE 4: RESUMEN DE ADOPTION
# ============================================================================
Write-Section "Fase 4: Adoption por Producto"

$TotalUsers = $AllUsers.Count
$AdoptionSummary = [System.Collections.Generic.List[object]]::new()

foreach ($Group in $CategoryGroups.Keys) {
    foreach ($Cat in $CategoryGroups[$Group]) {
        $Enabled  = $AdoptionEnabled[$Cat]
        $Disabled = $AdoptionDisabled[$Cat]
        $PctEnabled = if ($TotalUsers -gt 0) { [math]::Round(($Enabled / $TotalUsers) * 100, 1) } else { 0 }

        $AdoptionSummary.Add([PSCustomObject]@{
            CategoryGroup = $Group
            Product       = $Cat
            UsersEnabled  = $Enabled
            UsersDisabled = $Disabled
            TotalUsers    = $TotalUsers
            PctEnabled    = $PctEnabled
        })

        if ($Enabled -gt 0 -or $Disabled -gt 0) {
            $Bar = "#" * [math]::Max(1, [math]::Round($PctEnabled / 5))
            $DisabledNote = if ($Disabled -gt 0) { " ($Disabled deshabilitados)" } else { "" }
            $Color = if ($PctEnabled -gt 50) { "Green" } elseif ($PctEnabled -gt 20) { "Yellow" } else { "Red" }
            Write-Host ("  {0,-40} {1,5} activos ({2,5}%) [{3}]{4}" -f $Cat, $Enabled, $PctEnabled, $Bar, $DisabledNote) -ForegroundColor $Color
        }
    }
}

$AdoptionCsvPath = Join-Path $OutputPath "${Timestamp}_03_Adoption.csv"
$AdoptionSummary | Export-Csv -Path $AdoptionCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "Adoption: $AdoptionCsvPath"

# ============================================================================
# FASE 4b: CAPACIDAD vs USO POR PRODUCTO (OVERLICENSING)
# ============================================================================
Write-Section "Fase 4b: Capacidad vs Uso (Overlicensing)"

# Para cada producto, calcular cuantos seats totales hay disponibles
# sumando los Total de cada SKU que lo incluye, y comparar con uso real
$CapacitySummary = [System.Collections.Generic.List[object]]::new()

# Pre-calcular overlap por categoria: cuantos usuarios tienen duplicado en cada categoria
$OverlapByCategory = @{}
foreach ($Dup in $DuplicateReport) {
    $dCat = $Dup.DuplicateProduct
    if (-not $OverlapByCategory.ContainsKey($dCat)) { $OverlapByCategory[$dCat] = 0 }
    $OverlapByCategory[$dCat]++
}

foreach ($Cat in $SecurityCategories) {
    # Sumar seats de todos los SKUs que incluyen este producto
    $TotalSeats = 0
    $SkuCount = 0
    $ProvidedBy = [System.Collections.Generic.List[string]]::new()
    foreach ($Sku in $SubscribedSkus) {
        $SkuId = $Sku.SkuId.ToString()
        if ($SkuCategories.ContainsKey($SkuId) -and ($SkuCategories[$SkuId] -contains $Cat)) {
            $SkuEnabled = $Sku.PrepaidUnits.Enabled
            # Skip SKUs with absurd PrepaidUnits — Microsoft uses values like 1,000,000 as
            # "unlimited" / infrastructure indicators (e.g. PREMIUM_ENCRYPTION in add-on SKUs).
            # Threshold: any single SKU with > 5x the tenant user base is not a real seat count.
            $AbsurdThreshold = [math]::Max($TotalUsers * 5, 10000)
            if ($SkuEnabled -ge $AbsurdThreshold) {
                Write-Warn "SKU '$($Sku.SkuPartNumber)' tiene $SkuEnabled seats para '$Cat' — omitido (probablemente plan de infraestructura Microsoft)"
                continue
            }
            $TotalSeats += $SkuEnabled
            $SkuCount++
            $ProvidedBy.Add("$(Get-FriendlySkuName -SkuPartNumber $Sku.SkuPartNumber) ($SkuEnabled)")
        }
    }

    if ($TotalSeats -eq 0) { continue }

    $UsersActive   = $AdoptionEnabled[$Cat]
    $UsersDisabled = $AdoptionDisabled[$Cat]
    $OverlapUsers  = if ($OverlapByCategory.ContainsKey($Cat)) { $OverlapByCategory[$Cat] } else { 0 }
    $Unused        = $TotalSeats - $UsersActive
    $PctUsed       = [math]::Round(($UsersActive / $TotalSeats) * 100, 1)
    # Adoption real: usuarios unicos que tienen el feature / total de usuarios unicos que deberian tenerlo
    $UniqueUsersNeeded = [math]::Max($UsersActive, 1)
    $PctAdoption = [math]::Round(($UsersActive / [math]::Max($TotalUsers, 1)) * 100, 1)

    # Clasificar — distinguir overlap de bajo uso real
    $IsOverlap = ($SkuCount -gt 1 -and $OverlapUsers -gt 0 -and $OverlapUsers -ge ($UsersActive * 0.5))
    $Status = if ($UsersActive -gt $TotalSeats) { "UNDERLICENSED" }
              elseif ($IsOverlap) { "OVERLAP" }
              elseif ($PctUsed -lt 70) { "LOW_USAGE" }
              else { "OK" }

    $CapacityObj = [PSCustomObject]@{
        Product       = $Cat
        TotalSeats    = $TotalSeats
        UsersActive   = $UsersActive
        UsersDisabled = $UsersDisabled
        OverlapUsers  = $OverlapUsers
        Unused        = $Unused
        PctUsed       = $PctUsed
        PctAdoption   = $PctAdoption
        Status        = $Status
        ProvidedBy    = ($ProvidedBy -join " | ")
    }
    $CapacitySummary.Add($CapacityObj)

    $Color = switch ($Status) {
        "UNDERLICENSED" { "Red" }
        "OVERLAP"       { "Cyan" }
        "LOW_USAGE"     { "Yellow" }
        default         { "Green" }
    }
    $StatusLabel = switch ($Status) {
        "UNDERLICENSED" { "RIESGO: Mas uso que licencias!" }
        "OVERLAP"       { "Overlap: $OverlapUsers usuarios con feature en 2+ SKUs" }
        "LOW_USAGE"     { "Bajo uso ($Unused sin usar)" }
        default         { "OK" }
    }
    Write-Host ("  {0,-35} Seats:{1,4}  Activos:{2,4}  ({3,5}%)  {4}" -f $Cat, $TotalSeats, $UsersActive, $PctUsed, $StatusLabel) -ForegroundColor $Color
}

$CapacityCsvPath = Join-Path $OutputPath "${Timestamp}_07_Capacity.csv"
$CapacitySummary | Export-Csv -Path $CapacityCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "Capacidad: $CapacityCsvPath"

# ============================================================================
# FASE 5: RESUMEN DE WASTE
# ============================================================================
Write-Section "Fase 5: Analisis de Desperdicio"

Write-Host "  Cuentas deshabilitadas con licencia:  $WasteDisabledAccounts" -ForegroundColor $(if ($WasteDisabledAccounts -gt 0) { "Red" } else { "Green" })
Write-Host "  Usuarios inactivos ($InactiveDays+ dias):      $WasteInactiveUsers" -ForegroundColor $(if ($WasteInactiveUsers -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Usuarios con feature en 2+ SKUs:     $WasteDuplicateLicenses" -ForegroundColor $(if ($WasteDuplicateLicenses -gt 0) { "Yellow" } else { "Green" })

# Assignment methods ya calculados en el loop de usuarios
Write-Host "`n  Metodo de asignacion:" -ForegroundColor White
Write-Host "    Group-Based: $GroupAssigned" -ForegroundColor Gray
Write-Host "    Direct:      $DirectAssigned" -ForegroundColor Gray
Write-Host "    Mixto:       $MixedAssigned" -ForegroundColor Gray

# ============================================================================
# FASE 5b: RESUMEN POR DEPARTAMENTO (pre-agregado en el loop de usuarios)
# ============================================================================
Write-Section "Fase 5b: Resumen por Departamento"

$DeptSummary = [System.Collections.Generic.List[object]]::new()

foreach ($DeptEntry in ($DeptStats.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
    $DeptName  = $DeptEntry.Key
    $DeptCount = $DeptEntry.Value.Count
    $DeptSkuCounts = $DeptEntry.Value.SkuCounts
    $DeptCatCounts = $DeptEntry.Value.CatCounts

    $TopSkus = ($DeptSkuCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join " | "
    $ActiveProds = ($DeptCatCounts.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join " | "

    $DeptObj = [PSCustomObject]@{
        Department      = $DeptName
        UserCount       = $DeptCount
        TopSKUs         = $TopSkus
        ActiveProducts  = $ActiveProds
    }
    $DeptSummary.Add($DeptObj)

    Write-Host "  $DeptName : $DeptCount usuarios" -ForegroundColor White
}

# Exportar departamentos
$DeptCsvPath = Join-Path $OutputPath "${Timestamp}_06_Departments.csv"
$DeptSummary | Export-Csv -Path $DeptCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "Departamentos: $DeptCsvPath"

# ============================================================================
# FASE 5c: MATRIZ SKU vs PRODUCTOS
# ============================================================================
Write-Section "Fase 5c: Matriz SKU vs Productos incluidos"

$SkuMatrix = [System.Collections.Generic.List[object]]::new()

foreach ($Sku in $SubscribedSkus) {
    if ($Sku.PrepaidUnits.Enabled -eq 0 -and $Sku.ConsumedUnits -eq 0) { continue }

    $FriendlyName = Get-FriendlySkuName -SkuPartNumber $Sku.SkuPartNumber
    $SkuId = $Sku.SkuId.ToString()
    $Cats  = if ($SkuCategories.ContainsKey($SkuId)) { $SkuCategories[$SkuId] } else { @() }

    $MatrixObj = [PSCustomObject]@{
        SKU         = $FriendlyName
        PartNumber  = $Sku.SkuPartNumber
        Total       = $Sku.PrepaidUnits.Enabled
        Assigned    = $Sku.ConsumedUnits
    }

    foreach ($Cat in $SecurityCategories) {
        $HasIt = if ($Cats -contains $Cat) { "SI" } else { "" }
        $MatrixObj | Add-Member -NotePropertyName $Cat -NotePropertyValue $HasIt
    }

    $SkuMatrix.Add($MatrixObj)
    Write-Host "  $FriendlyName : $($Cats -join ', ')" -ForegroundColor Gray
}

# ============================================================================
Write-Section "Fase 6: Exportando datos para reporte HTML"

$ReportData = @{
    GeneratedAt              = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion            = "2.1"
    TenantName               = $TenantName
    TenantDomain             = $TenantDomain
    TenantId                 = $OrgId
    InactiveDays             = $InactiveDays
    TotalTenantUsers         = $TotalTenantUsers
    TotalMembers             = $TotalMembers
    TotalGuests              = $TotalGuests
    TotalLicensedUsers       = $TotalUsers
    SKUs                     = @($SkuSummary)
    SkuMatrix                = @($SkuMatrix)
    Adoption                 = @($AdoptionSummary)
    Capacity                 = @($CapacitySummary)
    Departments              = @($DeptSummary)
    Waste                    = @{
        DisabledAccounts     = $WasteDisabledAccounts
        InactiveUsers        = $WasteInactiveUsers
        DuplicateLicenses    = $WasteDuplicateLicenses
        DisabledPlans        = $WasteDisabledPlans
        TotalWasteUsers      = $WasteReport.Count
        Details              = @($WasteReport | Select-Object -First 500)
    }
    Duplicates               = @($DuplicateReport | Select-Object -First 500)
    AssignmentMethods        = @{
        Group                = $GroupAssigned
        Direct               = $DirectAssigned
        Mixed                = $MixedAssigned
    }
    CategoryGroups           = $CategoryGroups
    SecurityCategories       = $SecurityCategories
}

$JsonPath = Join-Path $OutputPath "${Timestamp}_report_data.json"
$ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-OK "JSON: $JsonPath"

# ============================================================================
# RESUMEN FINAL
# ============================================================================
$Duration = (Get-Date) - $ScriptStart

Write-Section "COMPLETADO en $([math]::Round($Duration.TotalSeconds)) segundos"
Write-Host "  Tenant:                $TenantName ($TenantDomain)" -ForegroundColor Green
Write-Host "  Usuarios con licencia: $TotalUsers" -ForegroundColor Green
Write-Host "  SKUs activos:          $($SkuSummary.Count)" -ForegroundColor Green
Write-Host "  Desperdicio detectado: $($WasteReport.Count) usuarios" -ForegroundColor $(if ($WasteReport.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Duplicados detectados: $($DuplicateReport.Count) entradas" -ForegroundColor $(if ($DuplicateReport.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "`n  Archivos en: $OutputPath" -ForegroundColor Cyan
Write-Host "    ${Timestamp}_01_SKUs.csv" -ForegroundColor White
Write-Host "    ${Timestamp}_02_Users.csv" -ForegroundColor White
Write-Host "    ${Timestamp}_03_Adoption.csv" -ForegroundColor White
if ($WasteReport.Count -gt 0)     { Write-Host "    ${Timestamp}_04_Waste.csv" -ForegroundColor White }
if ($DuplicateReport.Count -gt 0) { Write-Host "    ${Timestamp}_05_Duplicates.csv" -ForegroundColor White }
Write-Host "    ${Timestamp}_report_data.json" -ForegroundColor White
Write-Host "`n  Ejecuta .\Generate-HTMLReport.ps1 para el reporte visual" -ForegroundColor Yellow

if (-not $PreExistingSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion cerrada`n"
} else {
    Write-OK "Sesion mantenida (orquestador)`n"
}
