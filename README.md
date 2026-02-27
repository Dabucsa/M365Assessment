# M365 Security Assessment

Reporte HTML interactivo de seguridad y licenciamiento de Microsoft 365: licencias, adopción, Secure Score y recomendaciones.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-SDK-0078D4)
![Read Only](https://img.shields.io/badge/Tenant%20Impact-READ%20ONLY-green)
![Community](https://img.shields.io/badge/Project-Community-orange)

> **Proyecto comunitario.** No es un producto oficial de Microsoft. Desarrollado y mantenido por la comunidad para facilitar evaluaciones de seguridad en entornos M365. Úsalo bajo tu propio criterio y siempre valida los resultados con la documentación oficial.

---

## Inicio rápido

### 1. Desbloquear scripts (si los descargaste como ZIP)
```powershell
cd C:\Tools\M365Assessment
Get-ChildItem *.ps1 | Unblock-File
```
> Windows marca los archivos descargados de internet como "bloqueados". Sin este paso verás el error *"File cannot be loaded because running scripts is disabled"* o *"not digitally signed"*.

### 2. Ejecutar
```powershell
# Modo interactivo (te pregunta qué ejecutar)
.\Invoke-M365SecurityReport.ps1

# Todo de una, sin preguntas
.\Invoke-M365SecurityReport.ps1 -All

# Solo regenerar HTML con datos existentes
.\Invoke-M365SecurityReport.ps1 -ReportOnly

# Abrir reporte al finalizar
.\Invoke-M365SecurityReport.ps1 -All -Open
```

El script hace todo automáticamente:
- **Módulos**: si no tienes Microsoft.Graph instalado, te ofrece instalarlo con un solo "Y"
- **Login**: una sola ventana de autenticación de Microsoft (WAM) para toda la ejecución
- **Rol mínimo**: Global Reader

---

## ¿Qué genera?

Un reporte HTML single-file con 6 pestañas:

| Pestaña | Contenido |
|---------|-----------|
| **Resumen Ejecutivo** | KPIs, Secure Score, acciones prioritarias |
| **Licencias** | SKUs comprados vs asignados, grupo vs directa |
| **Usuarios** | Tabla filtrable con features por usuario |
| **SecOps** | Framework Assessment → Postura → Operación, portales, link a Guía de Operaciones |
| **Postura** | Secure Score desglosado, top recomendaciones |
| **Optimización** | Desperdicio, duplicados, inactivos, overlap |

Todos los datos se guardan en `./output/` con prefijo timestamp (CSV, JSON, HTML).

---

## 100% Read-Only

- No usa cmdlets `Set-*`, `New-*`, `Remove-*`, `Update-*`
- Las queries KQL consultan telemetría existente sin modificar nada
- No crea App Registrations, secrets ni service principals
- La autenticación es delegada e interactiva — sin tu sesión activa, 0 acceso

---

## Permisos requeridos (Scopes)

Todos son **delegados** y de **solo lectura**:

| Scope | Para qué |
|-------|----------|
| `Directory.Read.All` | SKUs, usuarios, grupos |
| `User.Read.All` | Licencias y features |
| `Organization.Read.All` | Info del tenant |
| `AuditLog.Read.All` | Sign-in activity |
| `Policy.Read.All` | Conditional Access |
| `UserAuthenticationMethod.Read.All` | MFA/SSPR |
| `IdentityRiskyUser.Read.All` | Usuarios riesgosos (P2) |
| `RoleManagement.Read.All` | PIM roles |
| `DeviceManagementManagedDevices.Read.All` | Intune |
| `SecurityEvents.Read.All` | Secure Score |
| `ThreatHunting.Read.All` | Advanced Hunting (E5) |
| `Reports.Read.All` | Copilot usage |

---

## Arquitectura

```
Invoke-M365SecurityReport.ps1          ← Orquestador
  ├── Get-M365LicensingData.ps1        ← SKUs, usuarios, waste, duplicados
  ├── Get-M365SecurityAdoption.ps1     ← MFA, CA, MDE, MDO, MDA, MDI, Intune
  ├── Get-M365SecureScore.ps1          ← Score + recomendaciones
  └── New-M365Report.ps1               ← Genera HTML desde datos
        └── report-template.html        ← Template con motor JS
```

---

## Parámetros

```powershell
# Orquestrador (recomendado)
.\Invoke-M365SecurityReport.ps1
    [-OutputPath ".\output"]     # Carpeta de salida
    [-InactiveDays 90]           # Días para marcar inactivo
    [-All]                       # Sin interacción
    [-ReportOnly]                # Solo HTML, sin recolección
    [-Open]                      # Abrir en navegador al terminar

# Scripts individuales
.\Get-M365LicensingData.ps1 [-TenantId "xxx"] [-OutputPath ".\output"] [-InactiveDays 90]
.\Get-M365SecurityAdoption.ps1 [-OutputPath ".\output"] [-InactiveDays 30]
.\Get-M365SecureScore.ps1 [-OutputPath ".\output"] [-TopRecommendations 20]
.\New-M365Report.ps1 [-OutputPath ".\output"] [-Open]
```

---

## Rendimiento estimado

No hace llamadas per-user. Todo via paginación y APIs agregadas.

| Tenant | Licensing | Adoption | Score | Total |
|--------|-----------|----------|-------|-------|
| 25K | 2-4 min | 1-3 min | ~10s | **4-8 min** |
| 50K | 4-8 min | 1-3 min | ~10s | **6-12 min** |
| 100K | 8-15 min | 2-4 min | ~10s | **11-20 min** |

---

## Tolerancia a fallos

- Cada módulo (Entra, MDE, MDO, MDA, MDI, Intune, Copilot) tiene su propio `try/catch` — si uno falla, los demás continúan
- **Graph API**: 3 reintentos con backoff exponencial (5s → 10s → 20s)
- **KQL (Advanced Hunting)**: 1 solo intento — si falla, salta sin esperar
- Errores 401/403/404 se detectan y se saltan inmediato
- Si no hay licencia E5 Security, las queries de Advanced Hunting se saltan automáticamente

---

## Solución de problemas

| Error | Solución |
|-------|----------|
| *"not digitally signed"* / *"running scripts is disabled"* | `Get-ChildItem *.ps1 \| Unblock-File` — desbloquea los archivos descargados de internet |
| *"File cannot be loaded"* con política RemoteSigned | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` y luego `Unblock-File` |
| *"Modulos de Microsoft Graph no encontrados"* | El script ofrece instalarlos automáticamente. Si falla: `Install-Module Microsoft.Graph -Scope CurrentUser` |
| *"Sin permisos para..."* | Falta un scope de Graph — verificar la tabla de permisos arriba |
| Pestaña vacía en el reporte | El módulo correspondiente falló — revisar logs en consola |
| *"No se encontró _report_data.json"* | Ejecutar `Get-M365LicensingData.ps1` primero (los demás dependen de él) |
| MFA muestra 0% | Normal si no hay licencia Entra ID P1/P2 |
| KQL queries fallan / Fase 4 lenta | Normal si es E3 — Advanced Hunting requiere E5 Security |
| Throttling (429) | Automático — el script espera y reintenta |

---

## Limpieza post-engagement

Después de correr el assessment **no queda nada activo** en el tenant. No hay secrets, no hay daemon access, no hay app registration personalizada.

Si el cliente quiere limpieza total:

**Revocar permisos** → Entra ID → Enterprise Apps → "Microsoft Graph PowerShell" → Permissions → Review permissions → Revocar

**Archivos locales** →
```powershell
Remove-Item -Recurse -Force .\output\*
Disconnect-MgGraph
```

> La app "Microsoft Graph PowerShell" (`14d82eec-...`) es de Microsoft, no tuya. La autenticación es 100% delegada — sin sesión activa del usuario, los permisos no hacen nada.

---

## Contribuir

1. Fork → `git checkout -b feature/mi-mejora` → commit → push → PR

---

> **Disclaimer:** Proyecto comunitario proporcionado "tal cual", sin garantías de ningún tipo. No es un producto oficial de Microsoft ni está respaldado por Microsoft. Los scripts son de solo lectura y no modifican la configuración del tenant. Siempre valida los resultados con la documentación oficial de Microsoft.
