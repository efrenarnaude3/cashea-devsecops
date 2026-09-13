<#
.SYNOPSIS
    Heimdall — driver del demo en Windows.

.DESCRIPTION
    Cada comando es un paso del demo y se puede correr solo. El orden de la
    reunión está en docs/demo-runbook.md.

        .\demo.ps1 check     Chequeo offline del repo + self-test del gate
        .\demo.ps1 gate      El gate decide sobre hallazgos de ejemplo
        .\demo.ps1 up        Crea el clúster kind e instala Kyverno
        .\demo.ps1 policy    Aplica la política de admisión (firma + registry)
        .\demo.ps1 deploy    Despliega la imagen firmada: la admite
        .\demo.ps1 deny      Intenta una imagen no autorizada: la rechaza
        .\demo.ps1 status    Qué hay corriendo y qué políticas están activas
        .\demo.ps1 down      Borra el clúster

    Los dos primeros comandos no necesitan Docker ni red: sirven aunque todo lo
    demás falle.

.PARAMETER Owner
    Usuario u organización de GitHub dueño del repo y del registry (ghcr.io).

.PARAMETER Image
    Referencia completa de la imagen firmada. Por defecto se arma como
    ghcr.io/<owner>/heimdall-notes-api:latest

.EXAMPLE
    .\demo.ps1 check
    .\demo.ps1 up -Owner mi-usuario
    .\demo.ps1 deploy -Owner mi-usuario
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('check', 'gate', 'up', 'policy', 'deploy', 'deny', 'status', 'down', 'help')]
    [string]$Command = 'help',

    [string]$Owner = $env:HEIMDALL_OWNER,
    [string]$Repo = 'heimdall',
    [string]$Image = '',
    [string]$Namespace = 'notes-api',
    [string]$KyvernoVersion = 'v1.13.4',
    [string]$ClusterName = 'heimdall'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$rendered = Join-Path $root '.rendered'

function Write-Step([string]$text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Write-Ok([string]$text) { Write-Host "  OK  $text" -ForegroundColor Green }
function Write-Warn([string]$text) { Write-Host "  !!  $text" -ForegroundColor Yellow }
function Write-Err([string]$text) { Write-Host "  XX  $text" -ForegroundColor Red }

function Assert-Tool([string]$name, [string]$hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Falta '$name' en el PATH. $hint"
    }
}

function Resolve-Owner {
    if ([string]::IsNullOrWhiteSpace($script:Owner)) {
        throw "Falta el owner de GitHub. Pasalo con -Owner tu-usuario o seteá `$env:HEIMDALL_OWNER."
    }
    return $script:Owner.ToLowerInvariant()
}

function Resolve-Image {
    if (-not [string]::IsNullOrWhiteSpace($script:Image)) { return $script:Image }
    return "ghcr.io/$(Resolve-Owner)/heimdall-notes-api:latest"
}

function New-RenderedFile([string]$source, [hashtable]$replacements, [string]$targetName) {
    if (-not (Test-Path $rendered)) { New-Item -ItemType Directory -Path $rendered | Out-Null }
    $content = Get-Content -Raw -Path (Join-Path $root $source)
    foreach ($key in $replacements.Keys) {
        $content = $content.Replace($key, $replacements[$key])
    }
    $target = Join-Path $rendered $targetName
    # UTF-8 sin BOM: `Set-Content -Encoding UTF8` en PowerShell 5.1 escribe BOM,
    # y algunos parsers de YAML fallan con "error converting YAML to JSON" sin
    # decir que el problema son tres bytes invisibles al principio.
    [System.IO.File]::WriteAllText($target, $content, (New-Object System.Text.UTF8Encoding($false)))
    return $target
}

function Invoke-Check {
    Write-Step 'Chequeo offline del repositorio'
    Assert-Tool 'python' 'Instalá Python 3.11+ desde python.org'
    python -m pip install --quiet --disable-pip-version-check pyyaml
    python (Join-Path $root 'scripts\verify_repo.py')
    if ($LASTEXITCODE -ne 0) { throw 'El chequeo del repo falló.' }

    Write-Step 'Self-test del motor del gate'
    python (Join-Path $root 'scripts\gate.py') --self-test
    if ($LASTEXITCODE -ne 0) { throw 'El self-test del gate falló.' }
    Write-Ok 'El repo es coherente y la lógica de decisión está verificada.'
}

function Invoke-Gate {
    Write-Step 'El gate decide sobre los hallazgos de ejemplo'
    Assert-Tool 'python' 'Instalá Python 3.11+ desde python.org'
    python (Join-Path $root 'scripts\gate.py') `
        --findings (Join-Path $root 'demo\findings') `
        --gate (Join-Path $root 'appsec\gate.yaml') `
        --exceptions (Join-Path $root 'appsec\exceptions.yaml') `
        --out (Join-Path $root 'gate-report')

    $code = $LASTEXITCODE
    switch ($code) {
        0 { Write-Ok 'El gate dejó pasar la corrida (exit 0).' }
        1 { Write-Warn 'El gate BLOQUEÓ la corrida (exit 1). Es el comportamiento esperado del demo.' }
        2 { Write-Err 'Error de configuración: el gate no pudo decidir (exit 2).' }
    }
    Write-Host "`nReporte completo en gate-report.md" -ForegroundColor DarkGray
}

function Invoke-Up {
    Write-Step "Creando el clúster kind '$ClusterName'"
    Assert-Tool 'kind' 'choco install kind  (o https://kind.sigs.k8s.io)'
    Assert-Tool 'kubectl' 'choco install kubernetes-cli'

    $existing = kind get clusters 2>$null
    if ($existing -contains $ClusterName) {
        Write-Warn "El clúster ya existe, lo reuso."
    }
    else {
        kind create cluster --name $ClusterName --config (Join-Path $root 'deploy\kind\cluster.yaml')
        if ($LASTEXITCODE -ne 0) { throw 'No pude crear el clúster.' }
    }

    Write-Step "Instalando Kyverno $KyvernoVersion"
    kubectl apply -f "https://github.com/kyverno/kyverno/releases/download/$KyvernoVersion/install.yaml"
    if ($LASTEXITCODE -ne 0) { throw 'Falló la instalación de Kyverno.' }

    Write-Host '  Esperando a que Kyverno esté listo (puede tardar un par de minutos)...'
    # Primero los Deployments y después los Pods. `kubectl wait` sobre pods
    # recién aplicado el manifiesto devuelve "no matching resources found" al
    # instante, porque los Pods todavía no existen: fallaría en 2 segundos y
    # parecería un timeout de 300.
    kubectl -n kyverno rollout status deployment --timeout=300s
    if ($LASTEXITCODE -ne 0) { throw 'Los deployments de Kyverno no llegaron a estar listos.' }
    kubectl wait --for=condition=Ready pod -l app.kubernetes.io/part-of=kyverno -n kyverno --timeout=300s
    if ($LASTEXITCODE -ne 0) { throw 'Kyverno no llegó a estar listo.' }

    kubectl apply -f (Join-Path $root 'deploy\k8s\namespace.yaml')
    Write-Ok 'Clúster listo, Kyverno corriendo y namespace creado.'
}

function Invoke-Policy {
    Write-Step 'Aplicando la política de admisión'
    Assert-Tool 'kubectl' 'choco install kubernetes-cli'
    $ownerValue = Resolve-Owner

    $file = New-RenderedFile 'policy\verify-image-signature.yaml' @{
        '__GITHUB_OWNER__' = $ownerValue
        '__GITHUB_REPO__'  = $Repo
    } 'policy.yaml'

    kubectl apply -f $file
    if ($LASTEXITCODE -ne 0) { throw 'No pude aplicar la política.' }
    Write-Ok "Política activa. Solo se admiten imágenes de ghcr.io/$ownerValue firmadas por el workflow de $ownerValue/$Repo."
}

function Invoke-Deploy {
    Write-Step 'Desplegando la imagen firmada'
    Assert-Tool 'kubectl' 'choco install kubernetes-cli'
    $imageValue = Resolve-Image
    Write-Host "  Imagen: $imageValue"

    $file = New-RenderedFile 'deploy\k8s\deployment.yaml' @{ '__IMAGE__' = $imageValue } 'deployment.yaml'
    kubectl apply -f $file
    if ($LASTEXITCODE -ne 0) {
        Write-Err 'El deploy fue rechazado. Si la imagen todavía no está firmada, es el control funcionando.'
        return
    }
    kubectl apply -f (Join-Path $root 'deploy\k8s\service.yaml')

    Write-Host '  Esperando el rollout...'
    kubectl rollout status deployment/notes-api -n $Namespace --timeout=180s
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Pod admitido y corriendo. Probalo: curl http://localhost:8080/health'
    }
}

function Invoke-Deny {
    Write-Step 'Intentando desplegar una imagen que el pipeline no produjo'
    Assert-Tool 'kubectl' 'choco install kubernetes-cli'
    Write-Host '  Imagen: docker.io/library/nginx:1.27-alpine (legítima, pero de otro registry)'
    Write-Host ''

    # $ErrorActionPreference = 'Stop' + redirección de stderr de un comando
    # nativo hace que PowerShell trate cada línea de error como excepción
    # terminante. Sin esto, el paso más importante del demo muestra un stack
    # trace rojo en vez del mensaje del control de admisión.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = kubectl apply -f (Join-Path $root 'deploy\k8s\unsigned-pod.yaml') 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference

    $output | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    Write-Host ''

    if ($code -ne 0) {
        Write-Ok 'RECHAZADO por el control de admisión. Esto es el equivalente exacto de lo que Binary Authorization hace en Cloud Run.'
    }
    else {
        Write-Err 'El Pod fue admitido: la política no está activa. Corré `.\demo.ps1 policy` antes.'
    }
}

function Invoke-Status {
    Write-Step 'Estado del demo'
    kubectl get clusterpolicies.kyverno.io 2>$null
    Write-Host ''
    kubectl get pods -n $Namespace 2>$null
    Write-Host ''
    Write-Host 'Últimos eventos del namespace:' -ForegroundColor DarkGray
    kubectl get events -n $Namespace --sort-by=.lastTimestamp 2>$null | Select-Object -Last 10
}

function Invoke-Down {
    Write-Step "Borrando el clúster '$ClusterName'"
    Assert-Tool 'kind' 'choco install kind'
    kind delete cluster --name $ClusterName
    Write-Ok 'Listo. No quedó nada corriendo.'
}

function Show-Help {
    Get-Help $PSCommandPath -Detailed
}

switch ($Command) {
    'check' { Invoke-Check }
    'gate' { Invoke-Gate }
    'up' { Invoke-Up }
    'policy' { Invoke-Policy }
    'deploy' { Invoke-Deploy }
    'deny' { Invoke-Deny }
    'status' { Invoke-Status }
    'down' { Invoke-Down }
    default { Show-Help }
}
