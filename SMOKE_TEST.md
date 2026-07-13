# Validación de una corrida v4

## 1. Pruebas offline

~~~powershell
./Run-SmokeTest.ps1
~~~

Resultado esperado:

- cero FAIL;
- JavaScript válido;
- setup JavaScript ejecutado con DOM controlado;
- filas de recomendaciones y columnas 30/60/90 renderizadas;
- Secure Score por dominio, ranking y prioridad presentes;
- perfil schema 1.0, IDs únicos y pesos válidos;
- findings con ControlId, riesgo, confianza y prioridad;
- dos corridas de tendencia y deltas con null semantics;
- manifest Shareable sin identificadores y con hashes válidos;
- producto y part number de licenciamiento visibles;
- guía operacional con RACI, cadencias y playbooks;
- Shareable sin TenantId, dominio, email o propiedades legacy;
- renderer rechaza RunId mezclado;
- renderer rechaza schema legacy;
- HTML modo 600 en macOS/Linux.
- manifest modo 600 en macOS/Linux.

La advertencia de corrida real legacy es esperable hasta generar un assessment v4.

## 2. Ejecutar tenant

~~~powershell
./Invoke-M365SecurityReport.ps1 -All -KeepIntermediates
./Run-SmokeTest.ps1
~~~

Registrar:

- RunId;
- operador y rol usado;
- scopes consentidos;
- módulos success/warning/error;
- hora de inicio y término;
- excepciones aprobadas.

## 3. Integridad

Confirmar en los tres JSON:

- SchemaVersion 4.0;
- mismo RunId;
- mismo TenantFingerprint;
- GeneratedAt dentro de la misma ventana;
- Collection.Status documentado.

Confirmar en el manifest:

- AssessmentVersion y Profile.Version aprobados;
- SHA-256 de cada fuente y del HTML;
- GrantedScopes sin tokens o principals;
- Findings iguales a los inyectados en el HTML;
- ContainsUserObjects en false;
- ausencia de TenantId/TenantFingerprint bajo Shareable.

No usar AllowMixedSources para un assessment final.

## 4. Licensing

Cruzar con Microsoft 365 Admin Center:

- SKUs activos;
- Total y Assigned por SKU;
- unidades suspendidas o warning;
- service plans relevantes;
- TotalLicensedUsers agregado.
- nombre, part number y familia de cada entitlement de seguridad.

Si se espera E3 y `/subscribedSkus` no lo devuelve, confirmar el mismo tenant y contrastar Billing > Your products. No reclasificar EMS E5 como Microsoft 365 E3.

No validar ni presentar:

- usuarios únicos por producto;
- overlap;
- cuentas inactivas/deshabilitadas;
- planes apagados;
- precio o ahorro.

Esos datos no forman parte del alcance v4.

## 5. Entra

Cruzar con Entra:

- Security Defaults;
- total de políticas CA por estado;
- política para legacy auth;
- políticas dirigidas a roles;
- número de políticas con exclusiones;
- MFA capable y población del reporte;
- Global Administrators;
- risky users por nivel;
- asignaciones PIM;
- Access Reviews.

Las señales CA requieren revisión manual de:

- users, groups y roles incluidos;
- exclusiones y break-glass;
- target resources;
- client apps;
- device/platform/location conditions;
- grant y session controls.

No convertir BroadScopePolicyDetected en porcentaje de cobertura.

## 6. Defender XDR

Ejecutar las mismas ventanas en Advanced Hunting y confirmar:

- MDE: dcount DeviceId onboarded y usuarios observados;
- MDO: volumen y amenazas;
- MDA: apps/eventos agregados;
- MDI: dcount de Domain Controllers y logons;
- alertas por ServiceSource.

Si una consulta falla, la métrica correspondiente debe ser N/D, no cero. MDE no debe mostrar porcentaje de cobertura.

## 7. Intune

Cruzar:

- DevicesEnrolled;
- Compliant, NonCompliant y Unknown;
- CompliancePct;
- plataformas;
- StaleDevices con el umbral configurado.

Confirmar que el portal no está aplicando filtros distintos.

## 8. Copilot

Cruzar el resumen D30:

- EnabledUsers30d;
- ActiveUsers30d;
- AdoptionPct.

Registrar que la API es beta. No debe existir export por usuario.

## 9. Secure Score y Purview

Cruzar:

- Current, Max y Pct;
- score, máximo y porcentaje por dominio;
- benchmarks AllTenants, TotalSeats e IndustryTypes cuando estén disponibles;
- controles implementados, parciales, pendientes y Unknown;
- controles inválidos;
- recomendaciones top, PriorityRank y PriorityBand;
- AssessmentControlId, AssessmentPriorityScore, RiskSeverity y Confidence;
- controles MIP/Purview.

No usar puntos de Secure Score como probabilidad de riesgo o certificación.

## 10. HTML Shareable

Abrir todas las pestañas:

- Resumen;
- Postura;
- Licenciamiento;
- Recomendaciones;
- Plan 30/60/90;
- Guía operacional.

Confirmar:

- no aparece la card Optimización de Licencias;
- N/D se usa para evidencia ausente;
- módulos partial/error son visibles;
- la tabla de cobertura explica que estado representa calidad de recolección, no cumplimiento;
- recomendaciones están ordenadas por prioridad del assessment y permiten ordenar por ganancia potencial;
- tendencia no compara valores null ni marca contexto como regresión;
- no hay nombre/dominio/ID del tenant;
- no hay nombres de personas, equipos o aplicaciones;
- imprimir a PDF mantiene orden y legibilidad;
- vista móvil no desborda navegación o tablas.

## 11. Cierre

El assessment queda listo para distribución solo si:

- smoke test sin FAIL;
- diferencias contra portales explicadas;
- módulos sin evidencia documentados;
- owners y criterios de cierre revisados;
- retención y clasificación del archivo acordadas;
- reporte aprobado por seguridad.
