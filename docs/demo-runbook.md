# Runbook del demo

Doce minutos. Cada paso tiene el comando, lo que aparece en pantalla, y la frase
que lo explica.

Toda la secuencia de este runbook está verificada de punta a punta en Windows 11
con Docker Desktop, detrás de un gateway corporativo que intercepta TLS.

---

## Antes de entrar a la reunión

Esto lleva unos seis minutos y **no se hace en vivo**. El clúster tarda, y
esperar un `docker pull` delante de un CISO no le agrega nada al argumento.

```powershell
cd C:\dev\heimdall
.\demo.ps1 down                      # por si quedó algo de una prueba anterior
.\demo.ps1 up -Preload -Owner efrenarnaude3
.\demo.ps1 trust
.\demo.ps1 policy -Owner efrenarnaude3 -Repo cashea-devsecops
```

Checklist:

- [ ] Docker Desktop abierto y estable. Si se reinició solo, volvé a correr `up`.
- [ ] `.\demo.ps1 up -Preload` terminó con "Clúster listo, Kyverno corriendo".
- [ ] `.\demo.ps1 trust` terminó con "Kyverno ya puede validar la cadena TLS".
- [ ] `.\demo.ps1 policy` terminó con "Política activa".
- [ ] Última corrida de `ci-security` en verde, en la pestaña del navegador.
- [ ] `terraform -chdir=terraform init -backend=false` corrido una vez, para
      que el provider quede cacheado: `init` no necesita credenciales, pero sí red.
- [ ] La slide de R-005 abierta en otra pestaña.
- [ ] `kubectl -n notes-api delete deployment notes-api --ignore-not-found` —
      el paso 4 tiene que crear el Deployment en vivo, no encontrarlo hecho.

> **Por qué `trust` existe.** El gateway de Cloudflare re-firma todo el tráfico
> TLS de la laptop. Kyverno, para verificar una firma keyless, empieza bajando
> las raíces de Sigstore, y esa conexión llega firmada por una CA que el pod no
> conoce. `trust` le monta el bundle con esa CA. En la red de Cashea este paso
> deja de ser un comando y pasa a ser una decisión de arquitectura: está en
> `docs/operacion-en-red-corporativa.md`.

---

## Paso 1 — El repo se verifica a sí mismo (1 minuto)

```powershell
.\demo.ps1 check
```

Nueve chequeos en verde y el self-test del gate con sus quince casos.

> Antes de mostrar qué hace, muestro que no está roto. Esto corre sin red y sin
> cuenta de nube, así que corre igual en CI y en la máquina de cualquiera del
> equipo.

---

## Paso 2 — El gate decide (3 minutos)

```powershell
.\demo.ps1 gate
```

Sale bloqueado, con la tabla de qué bloquea y qué no. Mostrá las cuatro ramas:
el CRITICAL nuevo que bloquea, el que tiene excepción vigente, el legacy
anterior a la adopción, el que no tiene fix.

> El gate no escanea nada. Lee lo que Trivy y npm audit ya produjeron, y decide.
> Y no bloquea el backlog histórico: solo lo posterior a la fecha en que el repo
> adoptó el control. Si bloqueara todo lo abierto, el primer squad pediría
> apagarlo, y el control terminaría apagado con el costo político ya pagado.

### El número real

Abrí el Summary de la última corrida de `ci-security`. Ahí está el gate corrido
sobre el servicio de verdad, no sobre una fixture:

> **7 hallazgos bloqueantes sobre 99 evaluados.** Y los 7 son una sola causa:
> `multer`, que entra como dependencia transitiva de `@nestjs/platform-express`.
> Los otros 92 pasan con el motivo escrito al lado.

### El bypass con justificación

Abrí `appsec/exceptions.yaml` y mostrá la excepción de multer, que es real y
está escrita en respuesta a ese reporte:

```yaml
  - package: multer
    reason: >-
      Dependencia transitiva de @nestjs/platform-express. El servicio no expone
      ninguna ruta que acepte multipart/form-data ni usa FileInterceptor...
    approved_by: efren.arnaude
    expires_on: 2026-11-13
```

Y mostrá que la justificación es **verificable**, no una afirmación:

```powershell
Get-ChildItem -Recurse service\src -Filter *.ts |
  Select-String -Pattern "FileInterceptor|multipart|multer"
```

No devuelve nada.

> Los tres campos son obligatorios. Sacá `approved_by` y el gate falla con exit
> 2: error de configuración, no "todo bien". Así es como "0% de bypass sin
> justificación" deja de ser una intención y pasa a ser un mecanismo.

### La excepción que caduca

Cambiá `expires_on` a ayer y corré de nuevo:

```powershell
.\demo.ps1 gate      # vuelve a bloquear
```

> Nadie tiene que acordarse de revisar la excepción. Vence sola y el hallazgo
> vuelve a bloquear. Acordate de dejarla como estaba antes de seguir.

---

## Paso 3 — La imagen no autorizada, rechazada (2 minutos)

```powershell
.\demo.ps1 deny
```

```
admission webhook "validate.kyverno.svc-fail" denied the request
heimdall-admission:
  solo-registry-autorizado: 'validation error: Imagen de un registry no autorizado...'
```

> Esta es la parte que no depende del pipeline. Alguien con `kubectl` puede
> saltarse CI entero; no puede saltarse esto. Y fijate que la imagen es nginx
> oficial, perfectamente sana: la rechaza por su procedencia, no por su
> contenido.

> Si te preguntan cómo sabés que el rechazo vino de la política: el script lo
> verifica. No le alcanza con que `kubectl` falle, busca la frase del webhook en
> el mensaje. Un namespace inexistente también haría fallar el comando, y
> contar eso como "el control funcionó" sería mentir sin querer.

---

## Paso 4 — La imagen firmada, admitida (3 minutos)

```powershell
.\demo.ps1 deploy -Owner efrenarnaude3
curl.exe http://localhost:8080/health
```

```
deployment.apps/notes-api created
deployment "notes-api" successfully rolled out
{"status":"ok"}
```

> La misma política que rechazó la anterior admite esta, porque tiene una firma
> cosign emitida por el workflow de este repositorio. Keyless: la identidad del
> workflow es la clave, así que no hay material privado que rotar ni filtrar.

Mostrá la imagen que quedó corriendo:

```powershell
kubectl -n notes-api get pod -o jsonpath="{.items[0].spec.containers[0].image}"
```

> Kyverno reescribió el tag al digest verificado. Lo que está corriendo está
> pinneado a contenido inmutable, aunque el manifiesto diga `:latest`.

---

## Paso 5 — El mismo control en GCP (2 minutos)

```powershell
terraform -chdir=terraform validate
```

Y abrí `terraform/modules/binary-authorization/main.tf`.

> En Cashea esto es Binary Authorization sobre Cloud Run, y no tiene costo de
> licencia: se puede encender con la infraestructura de hoy sin esperar GKE. El
> Terraform está escrito, validado, y pasa Checkov y tfsec en CI. Lo único que
> falta para aplicarlo es un proyecto con facturación activa.
>
> Un detalle que es fácil de errar: Binary Authorization **no lee firmas de
> Sigstore**. Verifica occurrences de Container Analysis firmadas con KMS. Por
> eso el pipeline produce las dos cosas. Si alguien arma esto asumiendo que
> cosign alcanza, la política termina rechazando todas las imágenes y el
> síntoma no dice por qué.

---

## Si algo falla en vivo

**El clúster no levanta.** Pasá a los pasos 1, 2 y 5, que no necesitan Docker.
El gate y el Terraform son el grueso del contenido, y el número de 7 sobre 99
sale del Summary de CI, que está en el navegador.

**`deploy` es rechazado con un error de x509.** Falta `trust`, o Kyverno se
reinició y perdió el parche. Corré `.\demo.ps1 trust` y repetí. Si no sale en
un intento, no insistas: decí que el control está fallando cerrado ante una
cadena de confianza que no puede validar, que es el comportamiento correcto, y
mostrá la corrida de CI donde `cosign verify` pasa.

**El Pod queda en ImagePullBackOff.** La imagen está en el nodo pero la política
la pineó a un digest que no está registrado localmente. Se arregla recreando con
`up -Preload`, que ya registra las formas con digest. En vivo, no lo intentes:
seguí con el paso 5.

**Kyverno tarda.** Los `wait` tienen 300 segundos. Si se pasan, seguí con el
paso 5 y volvé después.

**CI está en rojo el lunes a la mañana.** Miralo antes de entrar. Si el gate
bloqueó algo nuevo, no es un problema: es la mejor demostración posible de que
está encendido de verdad. Abrí el Summary, mostrá qué bloqueó y por qué, y decí
que así se ve el control funcionando un lunes cualquiera.

---

## Lo que te van a preguntar

**¿Y si el squad necesita desplegar urgente?** La excepción se aprueba por PR en
minutos y vence en 90 días como máximo. Un break-glass sin fecha de vencimiento
es una decisión permanente disfrazada de urgencia.

**¿Esto no frena a los equipos?** El repo arranca en `preview`, que mide sin
bloquear. Este repo estuvo en preview, produjo el número, se revisó, se escribió
la excepción, y recién ahí pasó a `enforce`. La discusión se hace con un dato y
no con una sensación.

**¿Por qué una excepción por paquete y no por CVE?** Porque multer tiene ocho
advisories con la misma causa y la misma justificación. Escribir ocho excepciones
idénticas no agrega control, agrega fricción, y la fricción es lo que hace que un
equipo abandone el proceso. El precio hay que decirlo: un advisory nuevo del
mismo paquete queda cubierto sin que nadie lo mire. Por eso vence.

**¿Por qué Kyverno y no Binary Authorization?** Por la cuenta de GCP, y lo digo
sin vueltas. El mecanismo es el mismo y el Terraform del camino real está en el
repo, validado y escaneado.

**¿Por qué `ClusterPolicy` si está deprecado?** Kyverno mismo lo avisa al
aplicarla. La sucesora es `ImageValidatingPolicy`, con CEL. No la migré a doce
horas de esta reunión, y migrarla es justamente el tipo de trabajo que entra en
el piloto.

**El gate no deduplica entre fuentes.** Lo encontré corriéndolo sobre datos
reales: las mismas seis vulnerabilidades de multer aparecen como GHSA por npm
audit (sin fecha, así que bloquean) y como CVE por Trivy (con fecha anterior a
la adopción, así que no). Cada comportamiento por separado es correcto —sin
fecha no puedo probar que un hallazgo es viejo, y trato como nuevo lo que no
puedo probar—, pero la inconsistencia es real y está en el backlog del piloto.
