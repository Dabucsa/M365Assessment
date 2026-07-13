# Assurance y modelo de confianza

## Objetivo

Demostrar qué hace el assessment, qué datos procesa, dónde los escribe y qué controles limitan exposición o conclusiones incorrectas.

## Identidad y autorización

- Autenticación delegada e interactiva mediante Microsoft Graph PowerShell.
- No usa client secrets, certificados de aplicación ni credenciales persistidas por el proyecto.
- Solicita scopes según capacidades detectadas.
- Verifica scopes del token y tenant antes de recolectar.
- El operador no necesita Global Administrator como requisito del proyecto. Debe usarse el rol lector compatible definido por la organización.

El consentimiento OAuth no reemplaza RBAC del tenant. Graph puede exigir ambos.

## Operaciones de tenant

Los colectores no contienen cmdlets Graph de escritura. Las operaciones son:

- GET para configuración, reportes, conteos y Secure Score.
- POST a security/runHuntingQuery para consultas KQL de lectura.

El proyecto no crea, cambia, deshabilita, revoca ni elimina configuración de Microsoft 365.

## Flujo de datos

1. Microsoft Graph devuelve objetos agregados o propiedades mínimas.
2. Los colectores derivan conteos y señales.
3. JSON/CSV intermedios se escriben localmente.
4. El renderer valida RunId y fingerprint.
5. El perfil Shareable elimina identificadores del tenant y detalles de error.
6. El renderer normaliza findings mediante un perfil versionado.
7. El HTML queda autocontenido, con CSP que bloquea conexiones externas.
8. El manifest registra hashes, procedencia y scopes sin objetos de usuario.

No existe envío del reporte a servicios externos.

Excepciones de red fuera de la recolección:

- Install-Module usa PSGallery solo si el usuario confirma la instalación.
- Sign-Scripts.ps1 con Sign puede contactar un timestamp server y enviar el resumen criptográfico de la firma, no los archivos.
- Los links a portales solo navegan cuando el usuario los abre.

## Minimización

Licensing:

- subscribedSkus;
- /users/$count;
- sin enumeración de usuarios.

Postura:

- MFA/SSPR mediante reportes agregados;
- Risky Users mediante conteos;
- PIM mediante asignaciones sin principalId;
- Global Administrators mediante id-only y conteo;
- MDI mediante dcount de DeviceName, sin nombres/FQDN;
- Intune con complianceState, operatingSystem y lastSyncDateTime;
- Copilot mediante resumen agregado D30.

El output no incluye UPN, email, display name, nombres de dispositivos, seriales, asuntos de correo ni listas de exclusiones.

## Integridad de evidencia

- RunId único con segundos y sufijo aleatorio.
- TenantFingerprint SHA-256 truncado para correlación local.
- SchemaVersion obligatorio.
- Fuentes con otro RunId o tenant se rechazan por defecto.
- Schemas legacy requieren autorización explícita y quedan marcados.
- Cualquier consulta sin evidencia produce null/N/D, no cero.
- ModuleStatus diferencia success, warning, error, unknown, skipped y notApplicable.
- ModuleStatus representa calidad de recolección, no postura ni cumplimiento.
- El ranking original de Secure Score conserva puntos recuperables; la prioridad del assessment es una clasificación metodológica y no una severidad oficial de Microsoft.
- Los findings v4.2 usan ControlId estable y separan RiskSeverity, Confidence y PriorityScore.
- Critical requiere RiskSeverity Critical; los puntos por sí solos no elevan un control a crítico.
- La historia reemplaza el mismo RunId y no calcula deltas con valores null.

## Manifest de auditoría

- Registra SHA-256 del HTML, perfil y fuentes.
- Registra versiones de schema/script, estado de colección y endpoints declarados.
- Conserva únicamente nombres de scopes, nunca tokens o contexto de sesión.
- Usa el mismo catálogo y findings inyectados en el HTML.
- Shareable omite TenantId y TenantFingerprint; Internal puede conservar fingerprint.
- Se protege con modo 600 y se retiene junto al HTML.

## Seguridad del HTML

- Sin JavaScript, CSS, fuentes o imágenes remotas.
- CSP: default-src none y connect-src none.
- base-uri, form-action, object-src y frame-src bloqueados.
- Datos dinámicos renderizados con textContent.
- Menor y mayor se escapan antes de inyectar JSON en script.
- Links externos usan noopener, noreferrer y no-referrer.
- CSV antepone apóstrofo a celdas con prefijos de fórmula, incluso tras whitespace.

## Protección local

En macOS/Linux:

- directorio output en modo 700;
- JSON, CSV, historia y HTML en modo 600.

En Windows se usan ACL heredadas. Debe verificarse que la carpeta tenga acceso restringido.

Sin KeepIntermediates, los archivos fuente se mueven a la Papelera. Esto reduce exposición accidental, pero no es borrado seguro. La eliminación definitiva depende del procedimiento del cliente.

## Límites de assurance

- Read-only reduce impacto, pero los scopes permiten leer información sensible.
- El HTML Shareable sigue siendo un documento confidencial.
- Un booleano de política no prueba cobertura o eficacia.
- Secure Score no es certificación.
- Los endpoints beta pueden cambiar.
- El código no puede demostrar por sí solo que el dispositivo local, PowerShell, módulos instalados o cuenta del operador estén libres de compromiso.

## Verificación

Ejecutar:

~~~powershell
./Run-SmokeTest.ps1
./Sign-Scripts.ps1
~~~

Run-SmokeTest valida fixtures maliciosos, CSP, escaping, schemas, mezcla de fuentes, perfiles, tendencias, findings, manifest, hashes, null semantics, sintaxis JavaScript, ejecución DOM y permisos. Sign-Scripts incluye `assessment-profile.json` y `Test-ReportRuntime.js` en SHA256SUMS.txt; la firma Authenticode es opcional en Windows.
