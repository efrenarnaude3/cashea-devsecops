<#
.SYNOPSIS
    Heimdall — driver del demo en Windows.

.DESCRIPTION
    Cada comando es un paso del demo y se puede correr solo. El orden de la
    reunión está en docs/demo-runbook.md.

        .\demo.ps1 check     Chequeo offline del repo + self-test del gate
        .\demo.ps1 gate      El gate decide sobre hallazgos de ejemplo
        .\demo.ps1 up        Crea el clúster kind e instala Kyverno
                             Agregá -Preload si la red intercepta TLS
        .\demo.ps1 trust     Solo si la red intercepta TLS: le enseña a Kyverno
                             la CA del interceptor para que pueda verificar
        .\demo.ps1 policy    Aplica la política de admisión (firma + registry)
        .\demo.ps1 attest    Sube la exigencia: además de la firma, pide el
                             atestado firmado del veredicto del gate
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
    [ValidateSet('check', 'gate', 'up', 'trust', 'policy', 'attest', 'attest-negativo', 'deploy', 'deny', 'status', 'down', 'help')]
    [string]$Command = 'help',

    [string]$Owner = $env:HEIMDALL_OWNER,
    [string]$Repo = 'heimdall',
    [string]$Image = '',
    [string]$Namespace = 'notes-api',
    # Kyverno v1.19 es la release con soporte de la comunidad (ago-2026) y cubre
    # Kubernetes v1.33-v1.35. El nodo de kind está fijado en v1.34 dentro de esa
    # ventana, en deploy/kind/cluster.yaml. Las dos líneas se mueven juntas.
    [string]$KyvernoVersion = 'v1.19.0',

    # De dónde bajan las imágenes de Kyverno. El manifiesto oficial apunta a
    # reg.kyverno.io, pero ghcr.io/kyverno es el repositorio documentado del
    # proyecto y sirve las mismas imágenes. Se puede cambiar porque en una red
    # con inspección TLS corporativa no todos los registries son alcanzables por
    # igual, y eso no debería ser motivo para no poder correr el demo.
    [string]$KyvernoRegistry = 'ghcr.io',

    # Baja las imágenes con el Docker del host y las inyecta en el nodo, en vez
    # de dejar que el nodo las baje. Necesario en redes con inspección TLS, y
    # buena idea siempre: vuelve el arranque del demo determinista.
    [switch]$Preload,
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

function Assert-Cluster {
    # Sin clúster, kubectl cae al default http://localhost:8080 y devuelve un
    # error de conexión rechazada que no dice lo único que hace falta saber:
    # que todavía no corriste `up`.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    kubectl cluster-info --request-timeout=5s 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous

    if ($code -ne 0) {
        throw "No hay ningún clúster respondiendo. Corré primero: .\demo.ps1 up -Owner $script:Owner"
    }
}

function Assert-Ready {
    # Lo que `up` deja instalado: el CRD que hace válida a una ClusterPolicy y
    # el namespace donde se despliega. Si falta alguno, todos los comandos que
    # siguen fallan con un error que habla de otra cosa, y el demo se explica
    # mal en vivo.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    kubectl get crd clusterpolicies.kyverno.io 2>&1 | Out-Null
    $crd = $LASTEXITCODE
    kubectl get namespace $script:Namespace 2>&1 | Out-Null
    $ns = $LASTEXITCODE
    $ErrorActionPreference = $previous

    if ($crd -ne 0) {
        throw "Kyverno no está instalado del todo (falta el CRD de ClusterPolicy). Volvé a correr: .\demo.ps1 up -Owner $script:Owner"
    }
    if ($ns -ne 0) {
        throw "Falta el namespace '$script:Namespace'. Volvé a correr: .\demo.ps1 up -Owner $script:Owner"
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

function Import-Images([string]$manifestText) {
    # Precarga: bajar las imágenes con el Docker del host y meterlas en el nodo,
    # en vez de que el nodo las baje por su cuenta.
    #
    # Hace falta cuando la red intercepta TLS. En ese escenario el proxy
    # corporativo (o el antivirus) re-firma los certificados con su propia CA;
    # Windows la tiene instalada y por eso `docker pull` funciona, pero el nodo
    # de kind es un contenedor Debian con su propio bundle de certificados, que
    # no la conoce. El síntoma es siempre el mismo, contra cualquier registry:
    #
    #   x509: certificate signed by unknown authority
    #
    # La imagen se exporta desde el daemon del host y se importa en el containerd
    # del nodo, sin TLS y sin red de por medio. Combinado con imagePullPolicy
    # IfNotPresent, el clúster queda efectivamente air-gapped, lo que además hace
    # el demo reproducible y rápido.
    Assert-Tool 'docker' 'Abrí Docker Desktop'

    # Las imágenes salen del manifiesto, no de una lista escrita a mano: así no
    # se desincronizan cuando cambia la versión de Kyverno.
    $images = [regex]::Matches($manifestText, '(?m)^\s*image:\s*"?([^"\s]+)"?\s*$') |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique

    $images = @($images) + @(Resolve-Image) | Sort-Object -Unique

    $node = "$ClusterName-control-plane"
    $tar = Join-Path $rendered 'image-load.tar'

    Write-Step "Precargando $($images.Count) imagen(es) en el nodo"

    # docker y ctr escriben progreso a stderr. Con ErrorActionPreference='Stop'
    # eso es una excepción terminante, así que acá se baja a 'Continue' y los
    # fallos se detectan por $LASTEXITCODE, que es lo que realmente importa.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        foreach ($image in $images) {
            Write-Host "  $image"

            # --platform: sin esto Docker guarda el índice multiplataforma
            # completo y el tar arrastra referencias a otras arquitecturas.
            docker pull --quiet --platform linux/amd64 $image
            if ($LASTEXITCODE -ne 0) {
                throw "No pude bajar $image con Docker. Si esto también falla, el problema no es solo del nodo: revisá la salida a internet del host."
            }

            # Acá NO se usa `kind load docker-image`, y la razón es concreta: por
            # dentro hace `ctr images import --all-platforms`, que exige que
            # estén presentes TODOS los manifiestos que el índice menciona. Las
            # imágenes publicadas con buildx incluyen manifiestos de attestation
            # (provenance y SBOM) que Docker no baja al hacer pull de una sola
            # plataforma, así que la importación muere con:
            #
            #   ctr: content digest sha256:...: not found
            #
            # El digest que nombra no es el de la imagen: es el de un manifiesto
            # que el índice referencia y que nunca estuvo en disco. Haciendo el
            # import a mano sin --all-platforms, ctr trae solo la plataforma que
            # corresponde y el problema desaparece.
            #
            # Se copia el tar al nodo en vez de pipearlo porque PowerShell 5.1 no
            # tiene redirección de entrada (`<`), y pipear binario por el
            # pipeline de PowerShell corrompe los bytes.
            #
            # El destino es /var/tmp y NO /tmp. kind crea los nodos con un tmpfs
            # montado sobre /tmp; `docker cp` escribe en la capa de abajo del
            # contenedor, que el montaje tapa, así que el copy dice
            # "Successfully copied" y el archivo no existe para nadie más:
            #
            #   Successfully copied 52.3MB to heimdall-control-plane:/tmp/...
            #   ctr: open /tmp/image-load.tar: no such file or directory
            #
            # Las dos líneas son ciertas a la vez. /var/tmp no tiene tmpfs
            # encima.
            docker save $image -o $tar
            if ($LASTEXITCODE -ne 0) { throw "No pude exportar $image." }

            docker cp $tar "${node}:/var/tmp/image-load.tar"
            if ($LASTEXITCODE -ne 0) { throw "No pude copiar la imagen al nodo." }

            docker exec $node ctr --namespace=k8s.io images import --digests --snapshotter=overlayfs /var/tmp/image-load.tar
            if ($LASTEXITCODE -ne 0) { throw "No pude importar $image en el containerd del nodo." }

            docker exec $node rm -f /var/tmp/image-load.tar | Out-Null
            Remove-Item $tar -Force -ErrorAction SilentlyContinue

            # La imagen quedó en containerd con UN solo nombre: el tag. Pero
            # Kyverno, al admitir el Pod, reescribe la referencia al digest que
            # verificó (mutateDigest), y el kubelet termina pidiendo:
            #
            #   ghcr.io/owner/img:latest@sha256:2ca817...
            #
            # containerd busca por el string exacto de la referencia. Ese nombre
            # no existe en su store, así que sale a resolverlo al registry —y en
            # una red con inspección TLS, vuelve a fallar con x509. El síntoma
            # desorienta: la imagen está en el nodo y aun así da ImagePullBackOff.
            #
            # Por eso se registran también las formas con digest. Es exactamente
            # lo que hace falta para que un clúster air-gapped conviva con una
            # política que pinea digests, que es la combinación correcta: la
            # precarga no debería obligar a renunciar a la inmutabilidad.
            $row = docker exec $node ctr -n k8s.io images ls "name==$image" 2>&1 |
            Select-Object -Skip 1 | Select-Object -First 1
            $digest = ("$row" -split '\s+') | Where-Object { $_ -like 'sha256:*' } | Select-Object -First 1

            if ($digest) {
                $lastColon = $image.LastIndexOf(':')
                $lastSlash = $image.LastIndexOf('/')
                $repo = if ($lastColon -gt $lastSlash) { $image.Substring(0, $lastColon) } else { $image }

                docker exec $node ctr -n k8s.io images tag --force $image "$repo@$digest" | Out-Null
                docker exec $node ctr -n k8s.io images tag --force $image "$image@$digest" | Out-Null
                Write-Host "    también como @$digest" -ForegroundColor DarkGray
            }
            else {
                Write-Warn "No pude leer el digest de $image; si la política pinea digests, el kubelet va a intentar bajarla."
            }
        }
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    Write-Ok 'Imágenes disponibles en el nodo. El clúster ya no necesita salir a internet para arrancar.'
}

function Invoke-Up {
    Write-Step "Creando el clúster kind '$ClusterName'"
    Assert-Tool 'kind' 'choco install kind  (o https://kind.sigs.k8s.io)'
    Assert-Tool 'kubectl' 'choco install kubernetes-cli'

    # `kind get clusters` escribe "No kind clusters found." a stderr cuando no
    # hay ninguno, que es la situación normal la primera vez. Con
    # ErrorActionPreference = 'Stop', PowerShell convierte esa línea en una
    # excepción terminante y el script muere antes de crear nada.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $existing = @(kind get clusters 2>&1 | ForEach-Object { "$_".Trim() })
    $ErrorActionPreference = $previous

    if ($existing -contains $ClusterName) {
        # Reusar ahorra tres minutos, pero un clúster que ya existe conserva la
        # versión de Kubernetes con la que se creó: cambiar la imagen del nodo
        # en cluster.yaml no tiene ningún efecto hasta que se recrea.
        Write-Warn "El clúster ya existe, lo reuso. Si cambiaste la versión del nodo en deploy\kind\cluster.yaml, primero corré .\demo.ps1 down."
    }
    else {
        kind create cluster --name $ClusterName --config (Join-Path $root 'deploy\kind\cluster.yaml')
        if ($LASTEXITCODE -ne 0) { throw 'No pude crear el clúster.' }
    }

    Write-Step "Instalando Kyverno $KyvernoVersion"
    # --server-side no es una optimización: sin eso la instalación NO entra.
    #
    # El `kubectl apply` clásico guarda una copia del manifiesto completo en la
    # anotación kubectl.kubernetes.io/last-applied-configuration, para poder
    # calcular el diff del próximo apply. Los CRDs de ClusterPolicy y Policy de
    # Kyverno llevan el esquema entero con documentación y pesan más que el
    # límite de 262144 bytes que Kubernetes impone a las anotaciones de un
    # objeto. El error ("metadata.annotations: Too long") nunca menciona cuál es
    # la anotación ni quién la escribió, y el resto del manifiesto sí se aplica:
    # queda una instalación a medias, con los Deployments creados y dos CRDs
    # faltando. Por eso el síntoma aparece recién más tarde, como
    # 'no matches for kind "ClusterPolicy"'.
    #
    # Con server-side apply el estado deseado lo lleva el API server en
    # managedFields y la anotación no se escribe.
    #
    # --force-conflicts cubre el caso de un intento previo: los objetos que ya
    # entraron por client-side apply pertenecen a otro field manager y el
    # server-side apply los reclamaría con un conflicto.
    # El manifiesto se baja y se reescribe antes de aplicarlo, en vez de
    # aplicarlo directo desde la URL. Dos razones:
    #
    # 1. Permite apuntar las imágenes a otro registry sin usar Helm.
    # 2. Deja en .rendered/ exactamente lo que se le mandó al clúster, que es lo
    #    que uno quiere tener a mano cuando algo no arranca.
    if (-not (Test-Path $rendered)) { New-Item -ItemType Directory -Path $rendered | Out-Null }
    $installUrl = "https://github.com/kyverno/kyverno/releases/download/$KyvernoVersion/install.yaml"
    $installFile = Join-Path $rendered 'kyverno-install.yaml'

    Write-Host "  Bajando el manifiesto de $KyvernoVersion..."
    $manifest = (Invoke-WebRequest -Uri $installUrl -UseBasicParsing).Content
    if ($manifest -is [byte[]]) { $manifest = [System.Text.Encoding]::UTF8.GetString($manifest) }

    if ($KyvernoRegistry -ne 'reg.kyverno.io') {
        Write-Host "  Reescribiendo las imágenes: reg.kyverno.io -> $KyvernoRegistry"
        $manifest = $manifest.Replace('reg.kyverno.io/', "$KyvernoRegistry/")
    }
    [System.IO.File]::WriteAllText($installFile, $manifest, (New-Object System.Text.UTF8Encoding($false)))

    if ($Preload) { Import-Images $manifest }

    kubectl apply --server-side --force-conflicts -f $installFile
    if ($LASTEXITCODE -ne 0) { throw 'Falló la instalación de Kyverno.' }

    # Un CRD aceptado todavía no es un CRD servido: el API server tiene que
    # publicar el endpoint antes de que `kubectl apply` de una ClusterPolicy
    # sepa a qué recurso corresponde.
    kubectl wait --for=condition=Established crd/clusterpolicies.kyverno.io --timeout=120s
    if ($LASTEXITCODE -ne 0) { throw 'El CRD de ClusterPolicy no quedó registrado.' }

    Write-Host '  Esperando a que Kyverno esté listo (puede tardar un par de minutos)...'
    # Primero los Deployments y después los Pods. `kubectl wait` sobre pods
    # recién aplicado el manifiesto devuelve "no matching resources found" al
    # instante, porque los Pods todavía no existen: fallaría en 2 segundos y
    # parecería un timeout de 300.
    kubectl -n kyverno rollout status deployment --timeout=300s
    if ($LASTEXITCODE -ne 0) {
        # Un timeout de rollout no dice nada por sí solo, y es el punto donde
        # más fácil es perder veinte minutos adivinando. Estas tres consultas
        # separan las tres causas posibles: la imagen no baja (ImagePullBackOff),
        # el proceso arranca y muere (CrashLoopBackOff, casi siempre versión de
        # Kubernetes fuera de la ventana soportada), o el Pod nunca se programa
        # (Pending por falta de memoria en Docker Desktop).
        Write-Warn 'Kyverno no llegó a estar listo. Esto es lo que dice el clúster:'
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        kubectl -n kyverno get pods -o wide 2>&1
        Write-Host ''
        kubectl version -o yaml 2>&1 | Select-String -Pattern 'gitVersion'
        Write-Host ''
        kubectl -n kyverno get events --sort-by=.lastTimestamp 2>&1 | Select-Object -Last 15
        $ErrorActionPreference = $previous
        $hint = if ($Preload) {
            "Las imágenes ya estaban precargadas, así que no es la red. Mirá el STATUS de los Pods de arriba."
        }
        else {
            "Si los Pods dicen ImagePullBackOff con 'x509: certificate signed by unknown authority', el nodo no confía en la CA que está interceptando TLS en tu red. Corré: .\demo.ps1 down; .\demo.ps1 up -Preload -Owner $script:Owner"
        }
        throw "Los deployments de Kyverno no llegaron a estar listos. $hint"
    }
    kubectl wait --for=condition=Ready pod -l app.kubernetes.io/part-of=kyverno -n kyverno --timeout=300s
    if ($LASTEXITCODE -ne 0) { throw 'Kyverno no llegó a estar listo.' }

    kubectl apply -f (Join-Path $root 'deploy\k8s\namespace.yaml')
    Write-Ok 'Clúster listo, Kyverno corriendo y namespace creado.'
}

function Invoke-Trust {
    # Hace que Kyverno confíe en la CA que está interceptando TLS en esta red.
    #
    # Sin esto, la verificación keyless no puede ni empezar: cosign arranca
    # bajando las raíces de confianza de Sigstore desde tuf-repo-cdn.sigstore.dev
    # y esa conexión, como todas, llega re-firmada por el proxy. El pod de
    # Kyverno tiene el bundle de certificados de su imagen, que no conoce esa CA,
    # así que corta antes de tocar el registry.
    #
    # ES UNA DECISIÓN DE SEGURIDAD, no un detalle de configuración: instalar la
    # CA del interceptor es declarar que se confía en el interceptor. Para un
    # clúster local, efímero y de demo, es aceptable y es lo que hace cualquier
    # equipo de plataforma en una red corporativa. En un clúster productivo, la
    # misma acción significa que un tercero puede leer y reescribir el tráfico
    # TLS de los workloads, y eso se discute antes de hacerlo, no después.
    Write-Step 'Enseñándole a Kyverno la CA que intercepta TLS en esta red'
    Assert-Cluster

    # La CA sale de la propia conexión, no de una ruta escrita a mano: se abre un
    # TLS contra un host cualquiera, se arma la cadena y se toma la raíz. Así
    # funciona con cualquier proxy, sin saber de antemano cuál es.
    $probe = 'ghcr.io'
    $client = New-Object System.Net.Sockets.TcpClient($probe, 443)
    try {
        $stream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, { $true })
        $stream.AuthenticateAsClient($probe)
        $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]$stream.RemoteCertificate
    }
    finally {
        $client.Close()
    }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    [void]$chain.Build($leaf)
    $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate

    Write-Host "  Raíz de la cadena hacia ${probe}:" -ForegroundColor DarkGray
    Write-Host "    $($root.Subject)" -ForegroundColor DarkGray

    $pem = "-----BEGIN CERTIFICATE-----`n" +
    [Convert]::ToBase64String($root.RawData, 'InsertLineBreaks') +
    "`n-----END CERTIFICATE-----`n"

    # El bundle tiene que ser COMPLETO: montarlo reemplaza el archivo de la
    # imagen, así que si solo lleva la CA corporativa, Kyverno deja de confiar en
    # todo lo demás. Se parte del bundle del nodo y se le agrega la raíz.
    $node = "$ClusterName-control-plane"
    $bundle = Join-Path $rendered 'ca-certificates.crt'

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $base = docker exec $node cat /etc/ssl/certs/ca-certificates.crt 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($code -ne 0) { throw 'No pude leer el bundle de certificados del nodo.' }

    $text = (($base | ForEach-Object { "$_" }) -join "`n") + "`n" + $pem
    [System.IO.File]::WriteAllText($bundle, $text, (New-Object System.Text.UTF8Encoding($false)))

    kubectl -n kyverno delete configmap kyverno-ca-bundle --ignore-not-found | Out-Null
    kubectl -n kyverno create configmap kyverno-ca-bundle --from-file=ca-certificates.crt=$bundle
    if ($LASTEXITCODE -ne 0) { throw 'No pude crear el ConfigMap con el bundle.' }

    # El nombre del contenedor se lee del Deployment en vez de asumirlo. Un
    # strategic merge patch con un nombre que no existe no falla: agrega un
    # contenedor nuevo, y el Deployment queda roto de una forma difícil de ver.
    $container = kubectl -n kyverno get deployment kyverno-admission-controller -o jsonpath='{.spec.template.spec.containers[0].name}'
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
        throw 'No pude leer el nombre del contenedor de Kyverno.'
    }
    Write-Host "  Parcheando el contenedor '$container'" -ForegroundColor DarkGray

    $patch = @"
spec:
  template:
    spec:
      volumes:
        - name: corp-ca
          configMap:
            name: kyverno-ca-bundle
      containers:
        - name: $container
          volumeMounts:
            - name: corp-ca
              mountPath: /etc/ssl/certs/ca-certificates.crt
              subPath: ca-certificates.crt
              readOnly: true
"@
    $patchFile = Join-Path $rendered 'kyverno-ca-patch.yaml'
    [System.IO.File]::WriteAllText($patchFile, $patch, (New-Object System.Text.UTF8Encoding($false)))

    # --type=strategic, NO merge. Un JSON merge patch (RFC 7386) reemplaza las
    # listas enteras: el parche de arriba habría dejado el contenedor con solo
    # `name` y `volumeMounts`, borrando `image` y todo lo demás. El error lo dice
    # con precisión y conviene reconocerlo:
    #
    #   spec.template.spec.containers[0].image: Required value
    #
    # El strategic merge patch conoce las claves de mezcla de los tipos nativos
    # de Kubernetes —`name` para containers y volumes, `mountPath` para
    # volumeMounts— y fusiona por elemento en vez de reemplazar.
    kubectl -n kyverno patch deployment kyverno-admission-controller --type=strategic --patch-file $patchFile
    if ($LASTEXITCODE -ne 0) { throw 'No pude parchear el deployment de Kyverno.' }

    Write-Host '  Esperando a que Kyverno vuelva a levantar...'
    kubectl -n kyverno rollout status deployment/kyverno-admission-controller --timeout=180s
    if ($LASTEXITCODE -ne 0) { throw 'Kyverno no volvió a estar listo después del parche.' }

    Write-Ok 'Kyverno ya puede validar la cadena TLS de esta red. Volvé a correr: .\demo.ps1 deploy'
}

function Invoke-Policy {
    Write-Step 'Aplicando la política de admisión'
    Assert-Tool 'kubectl' 'winget install Kubernetes.kubectl'
    Assert-Cluster
    Assert-Ready
    $ownerValue = Resolve-Owner

    $file = New-RenderedFile 'policy\verify-image-signature.yaml' @{
        '__GITHUB_OWNER__' = $ownerValue
        '__GITHUB_REPO__'  = $Repo
    } 'policy.yaml'

    kubectl apply -f $file
    if ($LASTEXITCODE -ne 0) { throw 'No pude aplicar la política.' }
    Write-Ok "Política activa. Solo se admiten imágenes de ghcr.io/$ownerValue firmadas por el workflow de $ownerValue/$Repo."
}

function Invoke-Attest {
    # Enciende el control por atestación, encima del de firma. Va aparte de
    # `policy` a propósito: son dos niveles de exigencia distintos y poder
    # aplicarlos por separado es parte de mostrar cómo se adopta por etapas.
    Write-Step 'Exigiendo la atestación del gate, además de la firma'
    Assert-Tool 'kubectl' 'winget install Kubernetes.kubectl'
    Assert-Cluster
    Assert-Ready
    $ownerValue = Resolve-Owner

    $file = New-RenderedFile 'policy\require-gate-attestation.yaml' @{
        '__GITHUB_OWNER__' = $ownerValue
        '__GITHUB_REPO__'  = $Repo
    } 'attestation-policy.yaml'

    kubectl apply -f $file
    if ($LASTEXITCODE -ne 0) { throw 'No pude aplicar la política de atestación.' }

    Write-Ok 'Ahora no alcanza con que la imagen esté firmada: el pipeline tiene que haber declarado, y firmado, que el gate la aprobó en modo enforce.'
    Write-Host '  La imagen a desplegar tiene que venir de una corrida POSTERIOR a este cambio,' -ForegroundColor DarkGray
    Write-Host '  porque las anteriores no llevan el atestado.' -ForegroundColor DarkGray
    Write-Host '  Para probar que el control no es decorativo: .\demo.ps1 attest-negativo' -ForegroundColor DarkGray
}

function Invoke-AttestNegative {
    # La prueba de que el control por atestación hace algo.
    #
    # Una regla de verificación mal escrita puede pasar SIEMPRE, y desde afuera
    # se ve igual que una que funciona: el Pod se admite en los dos casos. La
    # única forma de distinguirlas es pedirle algo que no exista y confirmar que
    # rechaza.
    #
    # Acá se aplica la misma política con un predicateType inventado. La imagen
    # es la misma, la firma es la misma, el atestado real sigue estando: lo
    # único que cambia es que se exige un atestado que nadie emitió.
    Write-Step 'Prueba negativa: exigir un atestado que no existe'
    Assert-Tool 'kubectl' 'winget install Kubernetes.kubectl'
    Assert-Cluster
    Assert-Ready
    $ownerValue = Resolve-Owner

    $file = New-RenderedFile 'policy\require-gate-attestation.yaml' @{
        '__GITHUB_OWNER__'                                  = $ownerValue
        '__GITHUB_REPO__'                                   = $Repo
        'https://cashea.app/attestations/security-gate/v1'  = 'https://cashea.app/attestations/NO-EXISTE/v1'
    } 'attestation-policy-negativa.yaml'

    kubectl apply -f $file
    if ($LASTEXITCODE -ne 0) { throw 'No pude aplicar la política de prueba.' }

    Write-Host '  Política modificada. Ahora el deploy TIENE que ser rechazado.' -ForegroundColor DarkGray
    Write-Host '  Cuando termines, volvé a la buena con: .\demo.ps1 attest' -ForegroundColor DarkGray
}

function Invoke-Deploy {
    Write-Step 'Desplegando la imagen firmada'
    Assert-Tool 'kubectl' 'winget install Kubernetes.kubectl'
    Assert-Cluster
    Assert-Ready
    $imageValue = Resolve-Image
    Write-Host "  Imagen: $imageValue"

    $file = New-RenderedFile 'deploy\k8s\deployment.yaml' @{ '__IMAGE__' = $imageValue } 'deployment.yaml'

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = kubectl apply -f $file 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    $output | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    if ($code -ne 0) {
        # Mismo criterio que en Invoke-Deny, al revés: acá el rechazo es la mala
        # noticia, y hay que saber si vino de la política (la firma no verifica)
        # o de cualquier otra cosa.
        $text = ($output | ForEach-Object { "$_" }) -join "`n"
        if ($text -match 'admission webhook|kyverno|denied the request') {
            Write-Err 'La política rechazó la imagen. Revisá que el package de ghcr sea público y que la firma corresponda al workflow configurado en policy/verify-image-signature.yaml.'
        }
        else {
            Write-Err 'El apply falló por una causa ajena a la política. El mensaje de arriba dice cuál.'
        }
        return
    }
    kubectl apply -f (Join-Path $root 'deploy\k8s\service.yaml')

    Write-Host '  Esperando el rollout...'
    kubectl rollout status deployment/notes-api -n $Namespace --timeout=180s
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Pod admitido y corriendo. Probalo: curl.exe http://localhost:8080/health'
        return
    }

    # Llegar acá significa algo distinto de un rechazo, y la diferencia importa:
    # el Pod fue ADMITIDO —la firma verificó— y después no llegó a Ready. Eso ya
    # no es el control de admisión, es la aplicación o la imagen.
    Write-Warn 'El Pod fue admitido pero no llegó a Ready. La firma verificó; el problema es posterior.'
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    kubectl -n $Namespace get pods -o wide 2>&1
    Write-Host ''
    Write-Host 'Imagen que quedó en el Pod (Kyverno la reescribe al digest verificado):' -ForegroundColor DarkGray
    kubectl -n $Namespace get pods -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' 2>&1
    Write-Host ''
    Write-Host 'Últimos eventos:' -ForegroundColor DarkGray
    kubectl -n $Namespace get events --sort-by=.lastTimestamp 2>&1 | Select-Object -Last 12
    Write-Host ''
    Write-Host 'Logs del contenedor:' -ForegroundColor DarkGray
    kubectl -n $Namespace logs deployment/notes-api --tail=30 --all-containers 2>&1

    $ErrorActionPreference = $previous
}

function Invoke-Deny {
    Write-Step 'Intentando desplegar una imagen que el pipeline no produjo'
    Assert-Tool 'kubectl' 'winget install Kubernetes.kubectl'
    Assert-Cluster
    Assert-Ready
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

    if ($code -eq 0) {
        Write-Err 'El Pod fue admitido: la política no está activa. Corré `.\demo.ps1 policy` antes.'
        return
    }

    # Un exit code distinto de cero NO alcanza como prueba de que el control
    # actuó. `kubectl apply` también falla si el namespace no existe, si el YAML
    # está mal formado o si el clúster no responde, y cantar "rechazado por la
    # política" en esos casos es demostrar un control que no intervino. En una
    # demo frente al equipo de seguridad, ese falso positivo es peor que el
    # error: el error se arregla, la afirmación falsa se cree.
    #
    # Kyverno rechaza a través de un ValidatingWebhookConfiguration, así que su
    # negativa siempre llega como "admission webhook ... denied the request".
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    if ($text -match 'admission webhook|kyverno|denied the request') {
        Write-Ok 'RECHAZADO por el control de admisión. Esto es el equivalente exacto de lo que Binary Authorization hace en Cloud Run.'
    }
    else {
        Write-Err 'El apply falló, pero NO fue la política: el mensaje de arriba dice la causa real. Hasta que ahí diga "admission webhook ... denied the request", el control no quedó demostrado.'
    }
}

function Invoke-Status {
    Write-Step 'Estado del demo'
    # Mismo motivo que en Invoke-Up: cualquier mensaje a stderr de kubectl
    # sería una excepción terminante y el estado nunca se mostraría.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    kubectl get clusterpolicies.kyverno.io 2>&1
    Write-Host ''
    kubectl get pods -n $Namespace 2>&1
    Write-Host ''
    Write-Host 'Últimos eventos del namespace:' -ForegroundColor DarkGray
    kubectl get events -n $Namespace --sort-by=.lastTimestamp 2>&1 | Select-Object -Last 10

    $ErrorActionPreference = $previous
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
    'trust' { Invoke-Trust }
    'policy' { Invoke-Policy }
    'attest' { Invoke-Attest }
    'attest-negativo' { Invoke-AttestNegative }
    'deploy' { Invoke-Deploy }
    'deny' { Invoke-Deny }
    'status' { Invoke-Status }
    'down' { Invoke-Down }
    default { Show-Help }
}
