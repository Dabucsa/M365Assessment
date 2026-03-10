#Requires -Version 5.1
<#
.SYNOPSIS
    Genera el reporte HTML de M365 Security Assessment a partir de JSON/CSV.
.DESCRIPTION
    Lee los archivos de datos, construye un JSON compacto y lo inyecta en
    report-template.html reemplazando el placeholder __REPORT_DATA__.
    El template es HTML/JS puro, sin expresiones PowerShell.
.PARAMETER OutputPath
    Carpeta donde buscar los JSON/CSV y donde escribir el HTML. Default: .\output
.PARAMETER LicensingJson
    Ruta explicita al _report_data.json (auto-detecta si no se pasa).
.PARAMETER UsersCSV
    Ruta explicita al _02_Users.csv (opcional).
.PARAMETER AdoptionJson
    Ruta explicita al _security_adoption.json (opcional).
.PARAMETER SecureScoreJson
    Ruta explicita al _secure_score.json (opcional).
.PARAMETER TemplatePath
    Ruta al template HTML. Default: .\report-template.html junto al script.
.PARAMETER ReportName
    Nombre personalizado para el HTML de salida.
.PARAMETER Open
    Abrir el reporte en el browser al terminar.
.EXAMPLE
    .\New-M365Report.ps1 -OutputPath ".\output"
#>
param(
    [string]$OutputPath     = ".\output",
    [string]$LicensingJson,
    [string]$UsersCSV,
    [string]$AdoptionJson,
    [string]$SecureScoreJson,
    [string]$TemplatePath   = "$PSScriptRoot\report-template.html",
    [string]$ReportName,
    [switch]$Open
)
$ErrorActionPreference = "Stop"

# ── Carpeta de salida ──────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path

# ── Auto-detectar archivos ─────────────────────────────────────────────────
function Find-Latest([string]$Dir,[string]$Filter){
    Get-ChildItem $Dir -Filter $Filter -EA SilentlyContinue |
        Sort-Object LastWriteTime -Desc | Select-Object -First 1
}
if (-not $LicensingJson)   { $f=Find-Latest $OutputPath "*_report_data.json";       if($f){$LicensingJson  =$f.FullName} }
if (-not $UsersCSV)        { $f=Find-Latest $OutputPath "*_02_Users.csv";           if($f){$UsersCSV       =$f.FullName} }
if (-not $AdoptionJson)    { $f=Find-Latest $OutputPath "*_security_adoption.json"; if($f){$AdoptionJson   =$f.FullName} }
if (-not $SecureScoreJson) { $f=Find-Latest $OutputPath "*_secure_score.json";      if($f){$SecureScoreJson=$f.FullName} }

if (-not $LicensingJson -or -not (Test-Path $LicensingJson)) {
    Write-Error "No se encontró _report_data.json. Ejecuta Get-M365LicensingData.ps1 primero."
}
if (-not (Test-Path $TemplatePath)) { Write-Error "Template no encontrado: $TemplatePath" }

Write-Host "[M365 Report] Inyector v3.0 — modo simple replace" -ForegroundColor Cyan
Write-Host "  Licensing:   $LicensingJson"   -ForegroundColor Yellow
if ($UsersCSV)        { Write-Host "  Users CSV:   $UsersCSV"        -ForegroundColor Yellow }
if ($AdoptionJson)    { Write-Host "  Adoption:    $AdoptionJson"    -ForegroundColor Yellow }
if ($SecureScoreJson) { Write-Host "  SecureScore: $SecureScoreJson" -ForegroundColor Yellow }

# ── Cargar datos ──────────────────────────────────────────────────────────
$LicData   = Get-Content $LicensingJson -Raw -Encoding UTF8 | ConvertFrom-Json
$AdoptData = if ($AdoptionJson    -and (Test-Path $AdoptionJson))    { Get-Content $AdoptionJson    -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
$ScoreData = if ($SecureScoreJson -and (Test-Path $SecureScoreJson)) { Get-Content $SecureScoreJson -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
$Users     = if ($UsersCSV        -and (Test-Path $UsersCSV))        { Import-Csv $UsersCSV } else { @() }

# ── Enriquecer AdoptData con SecureScoreControls ──────────────────────────
if ($AdoptData -and $ScoreData -and $ScoreData.AllRecommendations) {
    $SvcMap = @{ "MDO"="MDO"; "MCAS"="MDA"; "MDATP"="MDE"; "Azure ATP"="MDI" }
    foreach ($Svc in $SvcMap.Keys) {
        $Key  = $SvcMap[$Svc]
        $Data = $AdoptData.$Key
        if ($Data -and -not $Data.SecureScoreControls) {
            $Ctrls = @($ScoreData.AllRecommendations | Where-Object { $_.Service -eq $Svc })
            if ($Ctrls.Count -gt 0) {
                $En = @($Ctrls | Where-Object { $_.ImplementationStatus -eq 'Implemented' }).Count
                $Pa = @($Ctrls | Where-Object { $_.CurrentScore -gt 0 -and $_.CurrentScore -lt $_.MaxScore }).Count
                $Data | Add-Member -NotePropertyName 'SecureScoreControls' -NotePropertyValue ([PSCustomObject]@{
                    Total=$Ctrls.Count; FullyEnabled=$En; Partial=$Pa; NotImplemented=($Ctrls.Count-$En-$Pa)
                }) -Force
            }
        }
    }
}

# ── Función helper ────────────────────────────────────────────────────────
function JEsc([string]$s){ if(-not $s){ return '' }; $s -replace '\\','\\\\' -replace '"','\"' -replace "`r",'' -replace "`n",' ' -replace "`t",' ' }

# ── Arrays compactos de usuarios ──────────────────────────────────────────
Write-Host "[*] Procesando usuarios ($($Users.Count) filas)..." -ForegroundColor Yellow
$SecurityCats = if ($LicData.SecurityCategories) { $LicData.SecurityCategories } else { @() }

# Separadores por grupo de categoría
$CatSepList = [System.Collections.Generic.List[int]]::new()
$PrevGrp = ""
for ($ci = 0; $ci -lt $SecurityCats.Count; $ci++) {
    $Cat = $SecurityCats[$ci]; $CurGrp = ""
    if ($LicData.CategoryGroups) {
        foreach ($G in $LicData.CategoryGroups.PSObject.Properties) {
            if ($G.Value -contains $Cat) { $CurGrp = $G.Name; break }
        }
    }
    if ($CurGrp -ne $PrevGrp -and $PrevGrp -ne "") { $CatSepList.Add($ci) }
    $PrevGrp = $CurGrp
}

# Nombres completos de categorías
$CatFullNames = @{
    "Entra_ID_P1"="Entra ID P1";"Entra_ID_P2"="Entra ID P2";"Entra_ID_Governance"="Entra ID Governance"
    "MDE_P1"="Defender for Endpoint P1";"MDE_P2"="Defender for Endpoint P2"
    "MDO_P1"="Defender for Office P1";"MDO_P2"="Defender for Office P2"
    "MDA"="Defender for Cloud Apps";"MDI"="Defender for Identity"
    "Intune_P1"="Intune Plan 1";"Intune_P2"="Intune Plan 2"
    "Purview_AIP_P1"="AIP P1";"Purview_AIP_P2"="AIP P2";"Purview_MIP_P1"="MIP P1";"Purview_MIP_P2"="MIP P2"
    "Purview_DLP"="Purview DLP";"Purview_Audit"="Purview Audit";"Purview_eDiscovery"="Purview eDiscovery"
    "Purview_InsiderRisk"="Insider Risk";"Purview_CommCompliance"="Comm Compliance"
    "Purview_DataLifecycle"="Data Lifecycle";"Copilot_M365"="M365 Copilot"
}
$CatMetaArr = $SecurityCats | ForEach-Object {
    $F = if ($CatFullNames.ContainsKey($_)) { $CatFullNames[$_] } else { $_ }
    "`"$($F -replace '"','\"')`""
}

# Usuarios compactos
$UList = [System.Collections.Generic.List[string]]::new()
foreach ($U in $Users) {
    $CV = [System.Collections.Generic.List[int]]::new()
    foreach ($Cat in $SecurityCats) {
        $V = $U.$Cat
        if ($V -eq "Enabled") { $CV.Add(1) } elseif ($V -eq "Disabled") { $CV.Add(-1) } else { $CV.Add(0) }
    }
    $St = 0
    if ($U.AccountEnabled -eq "False") { $St = $St -bor 1 }
    if ($U.IsInactive      -eq "True")  { $St = $St -bor 2 }
    if ($U.WasteFlags)                  { $St = $St -bor 4 }
    if ($U.WasteFlags -match 'DisabledPlans') { $St = $St -bor 8 }
    if ($U.DisabledPlans)               { $St = $St -bor 16 }
    $Mt = switch ($U.AssignmentMethod) { "Group" { 1 } "Group+Direct" { 2 } default { 0 } }
    $Ca = if ($U.HasConditionalAccess -eq "True") { 1 } else { 0 }
    $Dy = if ($U.DaysSinceSignIn -match '^\d+$') { $U.DaysSinceSignIn } else { "-1" }
    $UList.Add("[`"$(JEsc $U.DisplayName)`",`"$(JEsc $U.UPN)`",`"$(JEsc $U.Department)`",`"$(JEsc $U.AssignedSKUs)`",`"$(JEsc $U.LastSignIn)`",$Dy,$St,$Mt,$Ca,[$($CV -join ',')],`"$(JEsc $U.WasteFlags)`",`"$(JEsc $U.DisabledPlans)`"]")
}

# Waste compacto
$WList = [System.Collections.Generic.List[string]]::new()
if ($LicData.Waste.Details) {
    foreach ($W in $LicData.Waste.Details) {
        $Ae = if ($W.AccountEnabled -eq "True") { 1 } else { 0 }
        $WList.Add("[`"$(JEsc $W.DisplayName)`",`"$(JEsc $W.UPN)`",$Ae,`"$(JEsc $W.LastSignIn)`",`"$(JEsc $W.AssignedSKUs)`",`"$(JEsc $W.WasteReasons)`"]")
    }
}

# Duplicates compacto
$DList = [System.Collections.Generic.List[string]]::new()
if ($LicData.Duplicates) {
    foreach ($Dup in $LicData.Duplicates) {
        $DList.Add("[`"$(JEsc $Dup.DisplayName)`",`"$(JEsc $Dup.UPN)`",`"$(JEsc $Dup.DuplicateProduct)`",`"$(JEsc $Dup.ProvidedBySKUs)`"]")
    }
}

# Listas únicas para filtros
$UniqDepts = @($Users | ForEach-Object { $_.Department } | Where-Object { $_ } | Sort-Object -Unique)
$UniqSkus  = @($Users | ForEach-Object { $_.AssignedSKUs -split "\s*\|\s*" } | Where-Object { $_ } | Sort-Object -Unique)
$DeptsJson = "[" + (($UniqDepts | ForEach-Object { "`"$($_ -replace '"','\"')`"" }) -join ",") + "]"
$SkusJson  = "[" + (($UniqSkus  | ForEach-Object { "`"$($_ -replace '"','\"')`"" }) -join ",") + "]"

# ── Construir MasterJson ──────────────────────────────────────────────────
Write-Host "[*] Construyendo MasterJson..." -ForegroundColor Yellow
$MasterObj = [ordered]@{
    lic   = $LicData
    adopt = $AdoptData
    score = $ScoreData
}
# Serializar objeto base
$BaseJson = $MasterObj | ConvertTo-Json -Depth 15 -Compress

# Inyectar arrays compactos manualmente (los grandes no pasan bien por ConvertTo-Json -Compress)
$UsersJsonRaw   = "[" + ($UList  -join ",") + "]"
$WasteJsonRaw   = "[" + ($WList  -join ",") + "]"
$DupJsonRaw     = "[" + ($DList  -join ",") + "]"
$CatMetaJson    = "[" + ($CatMetaArr -join ",") + "]"
$CatSepJson     = "[" + ($CatSepList  -join ",") + "]"

# Quitar exactamente el último "}" del objeto raíz y anexar los campos extra
$BaseJson = $BaseJson.Substring(0, $BaseJson.Length - 1)
$MasterJson = $BaseJson `
    + ",`"__users`":" + $UsersJsonRaw `
    + ",`"__waste`":" + $WasteJsonRaw `
    + ",`"__dup`":"   + $DupJsonRaw   `
    + ",`"__catMeta`":" + $CatMetaJson `
    + ",`"__catSep`":"  + $CatSepJson  `
    + ",`"__depts`":"   + $DeptsJson   `
    + ",`"__skus`":"    + $SkusJson    `
    + "}"

# ── Inyectar en template y guardar ───────────────────────────────────────
Write-Host "[*] Inyectando datos en template HTML..." -ForegroundColor Yellow
$template = Get-Content $TemplatePath -Raw -Encoding UTF8

if ($template -notmatch '__REPORT_DATA__') {
    Write-Error "El template no contiene el placeholder __REPORT_DATA__. Asegúrate de usar report-template.html v3.0."
}

$html = $template.Replace('__REPORT_DATA__', $MasterJson)

# Resolver nombre de salida
$Ts        = (Get-Date).ToString('yyyyMMdd_HHmm')
$OutName   = if ($ReportName) { $ReportName } else { "${Ts}_M365_Security_Report.html" }
if (-not $OutName.EndsWith('.html')) { $OutName += '.html' }
$OutFile   = Join-Path $OutputPath $OutName

# Escribir UTF-8 sin BOM
[System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))

$SizeMB = [math]::Round((Get-Item $OutFile).Length / 1MB, 2)
Write-Host "[OK] Reporte generado: $OutFile ($SizeMB MB)" -ForegroundColor Green

if ($Open) {
    if ($IsMacOS) { & open $OutFile }
    elseif ($IsLinux) { & xdg-open $OutFile }
    else { Start-Process $OutFile }
}
return $OutFile
