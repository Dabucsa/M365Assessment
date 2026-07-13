# Modulos requeridos: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
# (El orquestador Invoke-M365SecurityReport.ps1 valida e instala automaticamente)

<#
.SYNOPSIS
    Microsoft 365 Licensing Assessment — inventario AGREGADO (sin usuarios)
.DESCRIPTION
    Conecta al tenant via Microsoft Graph y genera un inventario de licencias
    100% AGREGADO. NO enumera ni procesa usuarios (cero PII):
    - SKUs comprados vs asignados vs sin usar (desde /subscribedSkus)
    - Que productos de seguridad incluye cada SKU (matriz)
    - Resumen de compra de seguridad (E5/E3 core, add-ons)
    - Conteos de tenant/miembros/invitados/licenciados (via $count, sin traer usuarios)
    NO hace: detalle por-usuario, waste, duplicados, departamentos ni asignacion
    grupo/directa (eso requeriria enumerar usuarios y exponer PII).
.PARAMETER TenantId
    ID del tenant. Si se omite, Graph usa el tenant del usuario que se autentica.
.PARAMETER OutputPath
    Carpeta de salida (default: .\output)
.EXAMPLE
    .\Get-M365LicensingData.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
.NOTES
    Requiere consentimiento para LicenseAssignment.Read.All y User.Read.All.
    Modulos:  Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
    Instalar: Install-Module Microsoft.Graph -Scope CurrentUser
              (o individualmente: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement)
    Seguridad: Este script es 100% READ-ONLY. No modifica, crea ni elimina nada en el tenant.
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = ".\output",
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,
    [switch]$PreserveGraphSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$OnWindowsHost = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }

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

function Resolve-ContextualPlanCategory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlanName,

        [Parameter(Mandatory = $true)]
        [string[]]$SkuPlanNames,

        [Parameter(Mandatory = $false)]
        [string]$SkuPartNumber
    )

    $PlanNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in $SkuPlanNames) {
        if ($Name) { [void]$PlanNameSet.Add($Name) }
    }

    switch ($PlanName) {
        'MTP' {
            # MTP = Microsoft Threat Protection. En algunos bundles modernos/dev aparece
            # como plan paraguas sin exponer WINDEFATP/MDE_E5 por separado. Lo tratamos
            # como señal DERIVED de MDE_P2 solo cuando el SKU claramente se comporta como
            # bundle E5 Security/E5 full.
            $MdeSignals = @(
                'THREAT_INTELLIGENCE',
                'ATP_ENTERPRISE',
                'ADALLOM_S_STANDALONE',
                'ATA',
                'AAD_PREMIUM_P2',
                'MDO_P2',
                'MDA',
                'MDI',
                'ENTRA_ID_P2'
            )

            $SignalCount = @($MdeSignals | Where-Object { $PlanNameSet.Contains($_) }).Count
            if ($SignalCount -ge 2 -or $SkuPartNumber -eq 'DEVELOPERPACK_E5') {
                return 'MDE_P2'
            }
        }
        'MIP_S_Exchange' {
            # MIP_S_Exchange por si solo es DLP basico de Exchange y no debe inflar E5 Compliance.
            # Pero si el mismo SKU ya trae varias senales fuertes de Compliance avanzada, aceptamos
            # una clasificacion DERIVED hacia Purview_DLP para no perder DLP en bundles tipo E5/dev.
            $StrongComplianceSignals = @(
                'M365_ADVANCED_AUDITING',
                'EQUIVIO_ANALYTICS',
                'PURVIEW_EDISCOVERY',
                'INSIDER_RISK',
                'INSIDER_RISK_MANAGEMENT',
                'INSIDER_RISK_MANAGEMENT_PREMIUM',
                'RECORDS_MANAGEMENT',
                'INFORMATION_BARRIERS',
                'PREMIUM_ENCRYPTION',
                'CUSTOMER_KEY',
                'CustomerLockboxA_Enterprise',
                'LOCKBOX_ENTERPRISE',
                'PAM_ENTERPRISE',
                'MIP_S_CLP2',
                'RMS_S_PREMIUM2'
            )

            $SignalCount = @($StrongComplianceSignals | Where-Object { $PlanNameSet.Contains($_) }).Count
            if ($SignalCount -ge 2 -or $SkuPartNumber -eq 'DEVELOPERPACK_E5') {
                return 'Purview_DLP'
            }
        }
    }

    return $null
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
    "AAD_PREMIUM"                                = "Microsoft Entra ID P1"
    "AAD_PREMIUM_P2"                             = "Microsoft Entra ID P2"
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
    if ([string]::IsNullOrWhiteSpace($SkuPartNumber)) { return "(SKU desconocido)" }
    # SKU no mapeado (p.ej. producto nuevo): prettificar el part number para que sea legible.
    # El part number crudo sigue visible como subtitulo en la tabla, asi no se pierde informacion.
    return ($SkuPartNumber -replace '_', ' ').Trim()
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

function Get-GraphCount {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri `
        -Headers @{ ConsistencyLevel = 'eventual' } `
        -OutputType Json -ErrorAction Stop
    $Content = ([string]$Response).Trim().Trim('"')
    $Count = 0L
    if (-not [long]::TryParse($Content, [ref]$Count)) {
        throw "Graph no devolvio un conteo valido para '$Uri'."
    }
    return $Count
}

function Get-TenantFingerprint {
    param([Parameter(Mandatory = $true)][string]$TenantId)

    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($TenantId.ToLowerInvariant())
        $Hash = $Sha.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($Hash).Replace('-', '').Substring(0, 16).ToLowerInvariant())
    } finally {
        $Sha.Dispose()
    }
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
if (-not $OnWindowsHost) { & /bin/chmod 700 $OutputPath }
$OutputPrefix = if ($RunId) { $RunId } else { Get-Date -Format "yyyyMMdd_HHmm" }

# ============================================================================
# FASE 1: CONEXION
# ============================================================================
Write-Section "Fase 1: Conexion a Microsoft Graph"

# Licensing agregado: LicenseAssignment.Read.All es el permiso minimo para
# /subscribedSkus. User.Read.All se usa solo con /users/$count; no se descargan
# objetos de usuario.
$Scopes = @(
    "LicenseAssignment.Read.All",
    "User.Read.All"
)

try {
    $ManagedSession = $false
    try { $ExistingCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { $ExistingCtx = $null }
    if (Test-GraphContextRequirements -Context $ExistingCtx -RequiredScopes $Scopes -RequiredTenantId $TenantId) {
        $Context = $ExistingCtx
        Write-OK "Reusando sesion delegada existente"
    } else {
        if ($ExistingCtx -and $ExistingCtx.Account) {
            Write-Step "La sesion existente no cumple tenant/scopes requeridos; abriendo sesion dedicada..."
        }
        $ConnectParams = @{ Scopes = $Scopes; NoWelcome = $true; ContextScope = 'Process' }
        if ($TenantId) { $ConnectParams.TenantId = $TenantId }
        Connect-MgGraph @ConnectParams
        $Context = Get-MgContext
        $ManagedSession = $true
        Write-OK "Sesion delegada conectada"
    }
    Write-OK "Contexto Graph validado"
} catch {
    Write-Warn "No se pudo conectar: $_"
    exit 1
}

# ============================================================================
# FASE 2: TENANT + SKUs + REGISTRO DINAMICO DE SERVICE PLANS
# ============================================================================
Write-Section "Fase 2: Inventario de SKUs y Service Plans"

# La identidad del tenant no se consulta por defecto. El TenantId del contexto se
# conserva solo en el JSON intermedio para correlacion y se elimina del reporte
# compartible.
$OrgId = [string]$Context.TenantId
$TenantFingerprint = Get-TenantFingerprint -TenantId $OrgId
Write-OK "Tenant validado (fingerprint: $TenantFingerprint)"

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
    $SkuPlanNames = @($Sku.ServicePlans | ForEach-Object { $_.ServicePlanName } | Where-Object { $_ })

    foreach ($Plan in $Sku.ServicePlans) {
        $PlanId   = $Plan.ServicePlanId.ToString()
        $PlanName = $Plan.ServicePlanName

        # Clasificar por nombre
        $Category = $null
        if ($PlanNameToCategory.ContainsKey($PlanName)) {
            $Category = $PlanNameToCategory[$PlanName]
        } else {
            $Category = Resolve-ContextualPlanCategory -PlanName $PlanName -SkuPlanNames $SkuPlanNames -SkuPartNumber $Sku.SkuPartNumber
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
$UnmappedCsvPath = $null
if ($UnmappedList) {
    Write-Host "`n  Service Plans sin clasificar encontrados en el tenant:" -ForegroundColor DarkYellow
    foreach ($PlanName in $UnmappedList) {
        Write-Host "    - $PlanName" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Exportar lista completa para revision
    $UnmappedCsvPath = Join-Path $OutputPath "${OutputPrefix}_00_UnmappedPlans.csv"
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
$SkuCsvPath = Join-Path $OutputPath "${OutputPrefix}_01_SKUs.csv"
$SkuSummary | Export-Csv -Path $SkuCsvPath -NoTypeInformation -Encoding UTF8
Write-OK "SKUs exportados: $SkuCsvPath"

# Resumen de entitlements de seguridad para dashboard / renderer. Microsoft
# Graph no expone precio ni clasifica de forma confiable un SKU como pago/free;
# por eso este bloque no hace afirmaciones comerciales.
$CoreE5SkuPartNumbers = @(
    "SPE_E5",
    "SPE_E5_NOPSTNCONF",
    "SPE_E5_CALLINGMINUTES",
    "ENTERPRISEPREMIUM",
    "ENTERPRISEPREMIUM_NOPSTNCONF",
    "DEVELOPERPACK_E5",
    "SPE_E5_GOV",
    "ENTERPRISEPREMIUM_GOV"
)

$CoreE3SkuPartNumbers = @(
    "SPE_E3",
    "ENTERPRISEPACK",
    "SPE_E3_GOV",
    "ENTERPRISEPACK_GOV"
)

$SecurityEntitlementItems = [System.Collections.Generic.List[object]]::new()

foreach ($Sku in $SkuSummary) {
    $IncludedCategories = @()
    if (-not [string]::IsNullOrWhiteSpace($Sku.IncludedCategories)) {
        $IncludedCategories = @($Sku.IncludedCategories -split '\s*\|\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ($Sku.Total -le 0 -or $IncludedCategories.Count -eq 0) { continue }

    $Family = if ($CoreE5SkuPartNumbers -contains $Sku.SKU_PartNumber) { "Core E5" }
              elseif ($CoreE3SkuPartNumbers -contains $Sku.SKU_PartNumber) { "Core E3" }
              elseif ($Sku.SKU_PartNumber -match '(?i)(DEFENDER|MDO|MDATP|MDE|MDA|MDI|IDENTITY_THREAT_PROTECTION)') { "Security Suite / Defender" }
              elseif ($Sku.SKU_PartNumber -match '(?i)(INFORMATION_PROTECTION|COMPLIANCE|PURVIEW)') { "Compliance / Purview" }
              elseif ($IncludedCategories -match '^Entra_ID_|^Intune_' -or $Sku.SKU_PartNumber -match '(?i)(AAD|AZURE_AD|EMS)') { "Identity / EMS" }
              else { "Security Add-on" }

    $SecurityEntitlementItems.Add([PSCustomObject]@{
        FriendlyName        = $Sku.FriendlyName
        SKU_PartNumber      = $Sku.SKU_PartNumber
        Family              = $Family
        Assigned            = [int]$Sku.Assigned
        Total               = [int]$Sku.Total
        IncludedCategories  = @($IncludedCategories)
    })
}

$SecurityEntitlementItems = [System.Collections.Generic.List[object]]@(
    $SecurityEntitlementItems |
        Sort-Object -Property @{ Expression = 'Assigned'; Descending = $true }, @{ Expression = 'FriendlyName'; Descending = $false }
)

$CoreE5Assigned = 0
$CoreE3Assigned = 0
foreach ($Sku in $SkuSummary) {
    if ($CoreE5SkuPartNumbers -contains $Sku.SKU_PartNumber) {
        $CoreE5Assigned += [int]$Sku.Assigned
    }
    if ($CoreE3SkuPartNumbers -contains $Sku.SKU_PartNumber) {
        $CoreE3Assigned += [int]$Sku.Assigned
    }
}

$SecurityEntitlementSummary = @{
    CoreE5Assigned            = $CoreE5Assigned
    CoreE3Assigned            = $CoreE3Assigned
    SecurityRelevantSkus      = $SecurityEntitlementItems.Count
    TopSecurityEntitlements   = @($SecurityEntitlementItems | Select-Object -First 6)
    Notes                     = @(
        "Core E5/E3 refleja bundles base Microsoft 365 / Office 365.",
        "Los consumos por SKU son asignaciones, no usuarios unicos y pueden superponerse.",
        "Graph no informa precio; este resumen no clasifica gasto ni ahorro."
    )
}

# ============================================================================
# INVENTARIO AGREGADO -> DATOS PARA EL REPORTE
# ----------------------------------------------------------------------------
# Todo sale de /subscribedSkus (SKUs, matriz, categorias, resumen de compra):
# cero PII. Solo agregamos conteos via $count (que NO traen objetos usuario).
# Este colector NO enumera ni procesa usuarios: no hay CSV de usuarios, no hay
# detalle por-usuario, no hay forma de filtrar informacion personal.
# ============================================================================
Write-Section "Inventario agregado de licencias (sin descargar usuarios)"

# Conteos agregados via /$count (ConsistencyLevel eventual): la respuesta es un
# numero y no contiene objetos, nombres, UPN ni IDs de usuario.
$TotalTenantUsers = $null
$TotalLicensed    = $null
$TotalGuests      = $null
$CountFailures = [System.Collections.Generic.List[string]]::new()
try {
    $TotalTenantUsers = Get-GraphCount -Uri "https://graph.microsoft.com/v1.0/users/`$count"
} catch {
    $CountFailures.Add('TotalTenantUsers')
    Write-Warn "No se pudo contar usuarios del tenant: $_"
}
try {
    $TotalLicensed = Get-GraphCount -Uri "https://graph.microsoft.com/v1.0/users/`$count?`$filter=assignedLicenses/`$count ne 0"
} catch {
    $CountFailures.Add('TotalLicensedUsers')
    Write-Warn "No se pudo contar usuarios licenciados via `$count: $_"
}
# Invitados (guests) — conteo agregado, senal de superficie externa
try {
    $TotalGuests = Get-GraphCount -Uri "https://graph.microsoft.com/v1.0/users/`$count?`$filter=userType eq 'Guest'"
} catch {
    $CountFailures.Add('TotalGuests')
    Write-Warn "No se pudo contar invitados: $_"
}
$TotalMembers = if ($null -ne $TotalTenantUsers -and $null -ne $TotalGuests) { [Math]::Max(0, $TotalTenantUsers - $TotalGuests) } else { $null }
$CountSummary = @(foreach ($Value in @($TotalTenantUsers, $TotalMembers, $TotalGuests, $TotalLicensed)) {
    if ($null -eq $Value) { 'N/D' } else { $Value }
})
Write-OK "Tenant: $($CountSummary[0]) usuarios ($($CountSummary[1]) miembros, $($CountSummary[2]) invitados) | Licenciados: $($CountSummary[3]) (conteo agregado)"

# Matriz "que incluye cada licencia" — agregada, desde SubscribedSkus
$SkuMatrix = [System.Collections.Generic.List[object]]::new()
foreach ($Sku in $SubscribedSkus) {
    if ($Sku.PrepaidUnits.Enabled -eq 0 -and $Sku.ConsumedUnits -eq 0) { continue }
    $SkuIdStr = $Sku.SkuId.ToString()
    $Cats     = if ($SkuCategories.ContainsKey($SkuIdStr)) { $SkuCategories[$SkuIdStr] } else { @() }
    $MatrixObj = [PSCustomObject]@{
        SKU        = (Get-FriendlySkuName -SkuPartNumber $Sku.SkuPartNumber)
        PartNumber = $Sku.SkuPartNumber
        Total      = $Sku.PrepaidUnits.Enabled
        Assigned   = $Sku.ConsumedUnits
    }
    foreach ($Cat in $SecurityCategories) {
        $MatrixObj | Add-Member -NotePropertyName $Cat -NotePropertyValue $(if ($Cats -contains $Cat) { "SI" } else { "" })
    }
    $SkuMatrix.Add($MatrixObj)
}

Write-Section "Exportando datos para el reporte HTML"
$ReportData = @{
    RunId                   = $OutputPrefix
    GeneratedAt             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    ScriptVersion           = "4.0"
    SchemaVersion           = "4.0"
    TenantId                = $OrgId
    TenantFingerprint       = $TenantFingerprint
    TotalTenantUsers        = $TotalTenantUsers
    TotalMembers            = $TotalMembers
    TotalGuests             = $TotalGuests
    TotalLicensedUsers      = $TotalLicensed
    SKUs                    = @($SkuSummary)
    SkuMatrix               = @($SkuMatrix)
    SecurityCategories      = $SecurityCategories
    CategoryGroups          = $CategoryGroups
    SecurityEntitlementSummary = $SecurityEntitlementSummary
    Collection              = @{
        Status = if ($CountFailures.Count -eq 0) { "success" } else { "partial" }
        Source = "Microsoft Graph"
        Endpoints = @("/subscribedSkus", "/users/`$count")
        ContainsUserObjects = $false
        FailedMetrics = @($CountFailures)
    }
}

$JsonPath = Join-Path $OutputPath "${OutputPrefix}_report_data.json"
$ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
if (-not $OnWindowsHost) {
    foreach ($Artifact in @($JsonPath, $SkuCsvPath, $UnmappedCsvPath)) {
        if ($Artifact -and (Test-Path -LiteralPath $Artifact)) { & /bin/chmod 600 $Artifact }
    }
}
Write-OK "JSON (agregado, sin PII): $JsonPath"

# ============================================================================
# RESUMEN FINAL
# ============================================================================
$Duration = (Get-Date) - $ScriptStart
Write-Section "COMPLETADO en $([math]::Round($Duration.TotalSeconds)) segundos"
Write-Host "  Tenant fingerprint:    $TenantFingerprint" -ForegroundColor Green
Write-Host "  Usuarios con licencia: $($CountSummary[3]) (conteo agregado)" -ForegroundColor Green
Write-Host "  SKUs activos:          $($SkuSummary.Count)" -ForegroundColor Green
Write-Host "  PII: no se descargo ni escribio ningun dato de usuario" -ForegroundColor Green
Write-Host "`n  Archivos en: $OutputPath" -ForegroundColor Cyan
Write-Host "    ${OutputPrefix}_01_SKUs.csv" -ForegroundColor White
Write-Host "    ${OutputPrefix}_report_data.json" -ForegroundColor White

if ($ManagedSession -and -not $PreserveGraphSession) {
    Disconnect-MgGraph | Out-Null
    Write-OK "Sesion dedicada cerrada`n"
} else {
    Write-OK "Sesion Graph mantenida`n"
}
