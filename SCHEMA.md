# Contrato de datos v4

Todos los artefactos de una corrida v4 comparten RunId, SchemaVersion 4.0 y TenantFingerprint. El renderer rechaza diferencias por defecto.

## Reglas

- null significa que no existe evidencia suficiente.
- Cero significa que Graph confirmó el valor cero.
- Los conteos de SKU son asignaciones, no usuarios únicos.
- Las señales de política no demuestran cobertura.
- No se permiten objetos de usuario, UPN, email, display name ni nombres de dispositivo en output.

## Licensing

Archivo: RUNID_report_data.json

~~~json
{
  "RunId": "20260711_210000_ab12cd",
  "GeneratedAt": "2026-07-11 21:00:00",
  "ScriptVersion": "4.0",
  "SchemaVersion": "4.0",
  "TenantId": "guid",
  "TenantFingerprint": "16-hex",
  "TotalTenantUsers": 120,
  "TotalMembers": 110,
  "TotalGuests": 10,
  "TotalLicensedUsers": 95,
  "SKUs": [
    {
      "SKU_ID": "guid",
      "SKU_PartNumber": "SPE_E5",
      "FriendlyName": "Microsoft 365 E5",
      "Total": 100,
      "Assigned": 95,
      "Unassigned": 5,
      "PctUsed": 95,
      "IncludedCategories": "Entra_ID_P2 | MDE_P2"
    }
  ],
  "SecurityEntitlementSummary": {
    "CoreE5Assigned": 95,
    "CoreE3Assigned": 0,
    "SecurityRelevantSkus": 2,
    "TopSecurityEntitlements": [],
    "Notes": []
  },
  "Collection": {
    "Status": "success",
    "Source": "Microsoft Graph",
    "ContainsUserObjects": false,
    "FailedMetrics": []
  }
}
~~~

Los conteos de usuarios pueden ser null si falla /users/$count. Nunca se reemplazan por consumedUnits.

## Secure Score

Archivo: RUNID_secure_score.json

~~~json
{
  "RunId": "20260711_210000_ab12cd",
  "SchemaVersion": "4.0",
  "TenantFingerprint": "16-hex",
  "Collection": {
    "Status": "success",
    "FailedRequests": 0,
    "InvalidControls": 0
  },
  "Score": {
    "Current": 42.1,
    "Max": 100,
    "Pct": 42.1,
    "Comparative": {}
  },
  "Categories": [
    {
      "Category": "Identity",
      "Score": 20,
      "MaxScore": 50,
      "PctScore": 40,
      "Controls": 12
    }
  ],
  "Summary": {
    "TotalControls": 40,
    "Implemented": 12,
    "Partial": 5,
    "NotImplemented": 22,
    "Deprecated": 1
  },
  "AllRecommendations": [
    {
      "Id": "control-id",
      "Title": "Control",
      "Category": "Identity",
      "MaxScore": 10,
      "CurrentScore": 4,
      "Improvement": 6,
      "PriorityRank": 1,
      "PriorityBand": "High",
      "ImplementationStatus": "Partial",
      "DataQuality": "valid",
      "Service": "Entra"
    }
  ]
}
~~~

Un control con maxScore incoherente usa DataQuality invalid, estado Unknown y valores calculados null. PriorityRank ordena todos los controles accionables por Improvement descendente. PriorityBand usa High para 5 puntos o más, Medium para 2 a 4,9 y Low para menos de 2; es una clasificación derivada, no una severidad de Microsoft.

## Security Adoption

Archivo: RUNID_security_adoption.json

Campos principales:

~~~json
{
  "RunId": "20260711_210000_ab12cd",
  "SchemaVersion": "4.0",
  "TenantFingerprint": "16-hex",
  "AdvancedHuntingLookbackDays": 14,
  "Entra": {
    "ConditionalAccess": {
      "Total": 8,
      "Enabled": 5,
      "ReportOnly": 2,
      "Disabled": 1,
      "BroadScopePolicyDetected": true,
      "LegacyAuthBlockPolicyDetected": false,
      "RoleTargetedMfaPolicyDetected": true,
      "PoliciesWithExclusions": 3,
      "AssessmentConfidence": "limited",
      "AssessmentLimitation": "..."
    },
    "SecurityDefaults": { "Enabled": false },
    "GlobalAdmins": { "Count": 4 },
    "MFA": {
      "Capable": 90,
      "NotCapable": 10,
      "TotalUsers": 100,
      "PctCapable": 90,
      "Population": "members",
      "Source": "usersRegisteredByFeature"
    },
    "RiskyUsers": {
      "TotalAtRisk": 2,
      "High": 1,
      "Medium": 1,
      "Low": 0
    },
    "PIM": {
      "EligibleAssignments": 10,
      "EligibleRoles": 4,
      "ActiveAssignments": 6,
      "ActiveRoles": 3,
      "PermanentAssignments": 2,
      "PrincipalDetailCollected": false,
      "AssessmentLimitation": "Asignaciones, no personas unicas."
    }
  },
  "MDE": {
    "TelemetryStatus": "partial",
    "DevicesOnboarded": 80,
    "UniqueUsersObserved": null,
    "CoverageStatus": "notCalculated",
    "TelemetryWindowDays": 14
  },
  "Intune": {
    "TelemetryStatus": "collected",
    "DevicesEnrolled": 50,
    "Compliant": 45,
    "NonCompliant": 3,
    "Unknown": 2,
    "CompliancePct": 90,
    "StaleDevices": 4,
    "StaleThresholdDays": 30
  },
  "Copilot": {
    "TelemetryStatus": "collected",
    "EnabledUsers30d": 25,
    "ActiveUsers30d": 18,
    "AdoptionPct": 72,
    "Source": "getMicrosoft365CopilotUserCountSummary",
    "ApiVersion": "beta"
  },
  "ModuleStatus": {
    "MDE": {
      "status": "warning",
      "message": "MDE devolvio datos parciales.",
      "details": {}
    }
  }
}
~~~

MDO, MDA y MDI siguen el mismo patrón: TelemetryStatus, TelemetryWindowDays, agregados y AlertsWindow. Las consultas fallidas dejan únicamente sus métricas en null.

ModuleStatus.details existe en JSON intermedio para auditoría. El renderer lo elimina y conserva solo status y message.

## Master HTML

El HTML inyecta un objeto con:

~~~json
{
  "lic": {},
  "adopt": {},
  "score": {},
  "trend": [],
  "findings": [
    {
      "ControlId": "ENTRA-CA-LEGACY",
      "PriorityRank": 1,
      "PriorityBand": "Critical",
      "PriorityScore": 74,
      "RiskSeverity": "Critical",
      "Confidence": "Medium",
      "HorizonDays": 30,
      "Owner": "SecOps + Identidad",
      "Evidence": "...",
      "ValidationCriterion": "..."
    }
  ],
  "profile": {
    "Name": "Enterprise Default",
    "Version": "2026.07",
    "SchemaVersion": "1.0",
    "RiskModel": {},
    "Thresholds": {}
  },
  "meta": {
    "RunId": "20260711_210000_ab12cd",
    "PrivacyProfile": "Shareable",
    "IntegrityStatus": "verified",
    "LegacySources": [],
    "Sources": {},
    "AuditManifest": "RUNID_audit_manifest.json"
  }
}
~~~

IntegrityStatus puede ser:

- verified: fuentes v4 coherentes.
- override: mezcla aceptada explícitamente con AllowMixedSources.
- legacy-migrated: migración v3 explícita; no es evidencia v4 final.

En Shareable se eliminan TenantId, TenantName, TenantDomain y TenantFingerprint.

## Findings y prioridad

Cada finding tiene un ControlId estable. Los controles derivados de Secure Score usan `MS-SS-{id de Microsoft}`; los controles nativos usan IDs del catálogo del perfil.

El perfil default calcula PriorityScore con:

- 50% RiskSeverity;
- 20% Confidence;
- 20% SecureScoreGain;
- 10% Urgency.

PriorityBand se calcula con los umbrales del perfil. Critical requiere además RiskSeverity Critical. Cambiar pesos, umbrales o catálogo exige aumentar ProfileVersion.

## Tendencia

Cada entrada incluye RunId, ProfileVersion, Date, KPIs agregados y EvidenceComplete. El renderer reemplaza el mismo RunId al regenerar y conserva las últimas 12 corridas. Los deltas solo usan valores no null; una métrica ausente no se interpreta como cero.

## Audit manifest

Archivo: `RUNID_audit_manifest.json`

~~~json
{
  "ManifestVersion": "1.0",
  "AssessmentVersion": "4.2",
  "RunId": "20260711_210000_ab12cd",
  "PrivacyProfile": "Shareable",
  "IntegrityStatus": "verified",
  "ContainsUserObjects": false,
  "Profile": {
    "Name": "Enterprise Default",
    "Version": "2026.07",
    "Sha256": "64-hex"
  },
  "Sources": [
    {
      "Name": "licensing",
      "File": "RUNID_report_data.json",
      "Sha256": "64-hex",
      "SchemaVersion": "4.0",
      "CollectionStatus": "success"
    }
  ],
  "GrantedScopes": [],
  "ModuleStatus": {},
  "Findings": [],
  "ControlCatalog": [],
  "Report": {
    "File": "RUNID_M365_Security_Report.html",
    "Sha256": "64-hex"
  }
}
~~~

El manifest Shareable no contiene TenantId ni TenantFingerprint. Internal agrega TenantFingerprint para correlación, pero nunca objetos de usuario, tokens o principals.

## Compatibilidad

El renderer v4 rechaza schemas anteriores por defecto. AllowLegacySchema activa una migración conservadora:

- descarta cobertura CA y MDE inferida;
- elimina optimización y detalle por usuario;
- marca telemetría v3 no verificable como N/D;
- marca el HTML como legacy-migrated.
