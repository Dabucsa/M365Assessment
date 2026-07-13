# M365 Security Assessment v4.2

Assessment read-only de postura de seguridad y licenciamiento de Microsoft 365. Recolecta evidencia agregada con Microsoft Graph, genera un HTML autocontenido y entrega recomendaciones, plan 30/60/90 y guía operacional para CISO, SecOps, IAM y equipos de cuenta.

## Qué resuelve

- Inventario de SKUs, asignaciones, capacidad libre y service plans.
- Postura de Entra ID: Conditional Access, Security Defaults, MFA/SSPR agregado, Global Administrators, risky users, PIM y Access Reviews.
- Telemetría agregada de Defender XDR mediante Advanced Hunting.
- Cumplimiento y antigüedad de sincronización de Intune sin nombres, seriales ni usuarios.
- Uso agregado de Microsoft 365 Copilot.
- Microsoft Secure Score global, por dominio, benchmarks y recomendaciones priorizadas por puntos recuperables.
- Prioridad versionada que combina riesgo, confianza, ganancia Secure Score y urgencia.
- Plan de remediación con ControlId, owner, evidencia y criterio de cierre.
- Tendencias agregadas y detección de regresiones entre corridas comparables.
- Manifest de auditoría con hashes, procedencia, scopes y findings normalizados.
- Guía operacional con ciclo de madurez, RACI, cadencias, playbooks y consultas KQL agregadas.

## Límite de licenciamiento

El assessment no hace optimización de licencias por usuario. No enumera usuarios para calcular inactividad, cuentas deshabilitadas, overlap individual, asignación directa/grupo, planes apagados, precio o ahorro.

ConsumedUnits representa asignaciones por SKU. No debe sumarse entre SKUs para inferir usuarios únicos. El nombre de producto y el part number se toman de `/subscribedSkus`; un bundle EMS E5 no se presenta como Microsoft 365 E3. Microsoft Graph no entrega precio comercial, por lo que cualquier análisis financiero requiere una fuente comercial separada y aprobada.

## Principios de seguridad

- Delegated authentication interactiva, sin client secret.
- Todas las consultas de tenant usan Microsoft Graph.
- Sin cmdlets Graph de escritura.
- Los POST usados por Advanced Hunting son operaciones de consulta.
- RunId y fingerprint impiden mezclar corridas o tenants silenciosamente.
- El perfil Shareable es el default y elimina identificadores del tenant del HTML.
- CSP bloquea conexiones, objetos, formularios, frames, fuentes y recursos externos.
- El renderer usa textContent y neutraliza cierre de script, separadores JavaScript y CSV formula injection.
- En macOS/Linux, output usa modo 700 y artefactos modo 600.

El HTML sigue siendo confidencial porque revela postura, gaps y capacidades. Debe cifrarse en tránsito y reposo, limitarse por necesidad y eliminarse según la retención del cliente.

## Arquitectura

1. Get-M365LicensingData.ps1 obtiene subscribedSkus y conteos /users/$count.
2. Get-M365SecureScore.ps1 obtiene score, perfiles y recomendaciones.
3. Get-M365SecurityAdoption.ps1 recolecta postura por capacidad licenciada.
4. assessment-profile.json define umbrales, modelo de riesgo y catálogo de controles.
5. New-M365Report.ps1 valida integridad, genera findings y produce HTML + manifest.
6. Invoke-M365SecurityReport.ps1 coordina una corrida con RunId único.
7. Run-SmokeTest.ps1 valida offline seguridad y contrato del renderer.
8. Test-ReportRuntime.js ejecuta el template con un DOM controlado y confirma recomendaciones y plan.

## Requisitos

- PowerShell 7 recomendado; PowerShell 5.1 soportado en Windows.
- Microsoft.Graph.Authentication.
- Microsoft.Graph.Identity.DirectoryManagement.
- Cuenta work/school del tenant.
- Consentimiento para los scopes aplicables.

El orquestador puede ofrecer instalar módulos faltantes desde PSGallery. Esa instalación usa red y solo ocurre con confirmación interactiva.

## Ejecución

Corrida completa:

~~~powershell
./Invoke-M365SecurityReport.ps1 -All
~~~

Corrida completa conservando JSON/CSV para auditoría:

~~~powershell
./Invoke-M365SecurityReport.ps1 -All -KeepIntermediates
~~~

Perfil específico de cliente:

~~~powershell
./Invoke-M365SecurityReport.ps1 -All -ProfilePath ./assessment-profile.json
~~~

El perfil debe conservar schema 1.0, IDs únicos, controles obligatorios y pesos que sumen 1.0. Los cambios de perfil deben revisarse y versionarse como cambios metodológicos.

Reporte interno con identificador de tenant:

~~~powershell
./Invoke-M365SecurityReport.ps1 -All -PrivacyProfile Internal
~~~

Regenerar un reporte v4 existente:

~~~powershell
./Invoke-M365SecurityReport.ps1 -ReportOnly -RunId 20260711_210000_ab12cd
~~~

Migrar artefactos v3 solo como referencia histórica:

~~~powershell
./Invoke-M365SecurityReport.ps1 -ReportOnly -RunId 20260711_1957 -AllowLegacySchema
~~~

Un reporte legacy queda marcado legacy-migrated. No debe presentarse como evidencia v4 final.

## Scopes Graph

| Scope | Uso | Condición |
|---|---|---|
| LicenseAssignment.Read.All | subscribedSkus | Siempre |
| User.Read.All | Conteos /users/$count, sin objetos | Siempre |
| SecurityEvents.Read.All | Secure Score | Siempre en corrida completa |
| Policy.Read.All | Security Defaults y CA | Baseline universal; CA si hay P1 |
| RoleManagement.Read.Directory | Conteo de Global Administrators | Baseline universal |
| AuditLog.Read.All | MFA/SSPR agregado | Entra ID P1/P2 |
| IdentityRiskyUser.Read.All | Conteos de risky users | Entra ID P2 |
| RoleAssignmentSchedule.Read.Directory | Asignaciones PIM | Entra ID P2 |
| AccessReview.Read.All | Definiciones y estados | Entra Governance |
| ThreatHunting.Read.All | KQL agregado de Defender XDR | Defender detectado |
| DeviceManagementManagedDevices.Read.All | Estado/OS/lastSync de dispositivos | Intune |
| Reports.Read.All | Resumen agregado Copilot D30 | Copilot |

Los scopes OAuth y los roles administrativos del tenant son controles distintos. Según la política del tenant, el operador puede necesitar un rol lector compatible además del consentimiento. No se recomienda asignar Global Administrator para ejecutar el assessment.

## Privacidad

### Shareable

- Elimina TenantId, nombre, dominio y fingerprint del HTML.
- No incluye UPN, email, display name, nombres/FQDN de equipos, seriales ni asuntos.
- Conserva solo agregados, estados y recomendaciones.

### Internal

- Puede conservar TenantId y fingerprint para correlación.
- Sigue sin incluir detalle por usuario o dispositivo.

Los JSON intermedios contienen identificadores de tenant y evidencia técnica. KeepIntermediates los conserva; sin ese switch se envían a la Papelera, lo que no equivale a borrado seguro.

## Interpretación

- success: fuente disponible y consulta completa.
- warning: evidencia parcial; los campos fallidos quedan null/N/D.
- error o unknown: no se debe inferir cero ni cumplimiento.
- skipped: módulo omitido por alcance o permiso.
- notApplicable: capacidad no detectada en licenciamiento.

ModuleStatus describe la calidad de la recolección del área o API, no el nivel de seguridad del control. Los JSON de Secure Score conservan la ganancia potencial original; el HTML aplica el modelo del perfil para producir la prioridad del assessment.

En v4.2 la prioridad del assessment reemplaza ese orden simple en el HTML: 50% riesgo, 20% confianza, 20% ganancia Secure Score y 10% urgencia en el perfil default. Critical solo se asigna cuando el riesgo base también es Critical. El modelo apoya decisiones, pero no sustituye aceptación formal de riesgo.

## Artefactos de salida

- `RUNID_M365_Security_Report.html`: reporte autocontenido Shareable o Internal.
- `RUNID_audit_manifest.json`: procedencia, hashes, scopes, estados, catálogo y findings.
- `RUNID_*.json/csv`: evidencia intermedia, solo cuando se usa KeepIntermediates.
- `_trend_FINGERPRINT.json`: historia agregada local para comparación entre corridas.

Sin KeepIntermediates se conservan HTML y manifest; los intermedios se envían a la Papelera.

Las señales CA prueban existencia de configuración, no cobertura efectiva. Exclusiones, aplicaciones, condiciones y cuentas de emergencia requieren validación manual.

MDE reporta dispositivos y usuarios observados, no porcentaje de cobertura. PIM reporta asignaciones, no personas únicas. Intune solo publica cero cuando Graph confirmó una colección vacía.

## Validación

Pruebas offline:

~~~powershell
./Run-SmokeTest.ps1
~~~

Prueba con tenant y cruce manual:

~~~powershell
./Run-SmokeTest.ps1 -RunFirst
~~~

Consulte SMOKE_TEST.md para validación contra portales y SCHEMA.md para el contrato de datos.

## Limitaciones

- Copilot usa un endpoint Microsoft Graph beta y puede cambiar.
- Los service plan names evolucionan; revise el CSV UnmappedPlans.
- Advanced Hunting depende de licenciamiento, permisos, retención y tablas habilitadas.
- Secure Score es una señal del proveedor, no certificación ni prueba completa de eficacia.
- La prioridad depende del perfil versionado y debe aprobarse para el contexto del cliente.
- El assessment no modifica configuración ni reemplaza revisión humana, threat modeling, pruebas de control o aceptación formal de riesgo.

Proyecto comunitario no oficial de Microsoft.
