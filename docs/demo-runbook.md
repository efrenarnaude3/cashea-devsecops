# Runbook del demo

Diez minutos, cinco pasos, en este orden. Cada paso tiene un comando, lo que se
ve en pantalla, y la frase que lo explica.

## Antes de entrar

- [ ] `npm install --package-lock-only` corrido dentro de `service/` y el
      lockfile commiteado. Sin esto no corre ni CI ni el `docker build`.
- [ ] Repo pusheado, última corrida de `ci-security` en verde.
- [ ] `.\demo.ps1 check` en verde: 8 de 9 chequeos, con el aviso del lockfile
      resuelto si ya lo commiteaste.
- [ ] El clúster ya creado (`.\demo.ps1 up`), porque tarda un par de minutos y
      no querés esperarlos en vivo.
- [ ] La política ya aplicada (`.\demo.ps1 policy`).
- [ ] `make tf-validate` corrido una vez, para que el provider de Terraform
      quede cacheado: `init` no necesita credenciales pero sí necesita red.
- [ ] La slide de R-005 abierta en otra pestaña.

## Paso 1 — El repo se verifica a sí mismo (1 minuto)

```powershell
.\demo.ps1 check
```

Ocho chequeos en verde y el self-test del gate con sus once casos.

> Antes de mostrar qué hace, muestro que no está roto. Esto corre sin red y sin
> cuenta de nube, así que también corre en CI y en la máquina de cualquiera del
> equipo.

## Paso 2 — El gate decide (3 minutos)

```powershell
.\demo.ps1 gate
```

Sale bloqueado, con la tabla de qué bloquea y qué no. Mostrá las cuatro ramas
en la salida: el CRITICAL nuevo que bloquea, el que tiene excepción vigente, el
legacy anterior a la adopción, el que no tiene fix.

> El gate no escanea nada. Lee lo que Trivy y npm audit ya produjeron y decide.
> Y no bloquea el backlog histórico: solo lo posterior a la fecha en que el repo
> adoptó el control. Si bloqueara los 107 hallazgos abiertos, el primer squad
> pediría apagarlo.

### El bypass con justificación

Agregá el hallazgo bloqueante a `appsec/exceptions.yaml`:

```yaml
  - id: CVE-2026-1000
    reason: >-
      Explicación concreta de por qué el riesgo es aceptable acá.
    approved_by: appsec
    expires_on: 2026-10-15
```

```powershell
.\demo.ps1 gate      # ahora pasa
```

> Los cuatro campos son obligatorios. Sacá `approved_by` y el gate falla con
> exit 2: error de configuración, no "todo bien". Así es como "0% de bypass sin
> justificación" deja de ser una intención y pasa a ser un mecanismo.

### La excepción que caducó

Cambiá `expires_on` a ayer y corré de nuevo:

```powershell
.\demo.ps1 gate      # vuelve a bloquear
```

> Nadie tiene que acordarse de revisar la excepción. Vence sola y el hallazgo
> vuelve a bloquear.

## Paso 3 — La imagen no autorizada, rechazada (2 minutos)

```powershell
.\demo.ps1 deny
```

El API server rechaza el Pod y muestra el mensaje de la política.

> Esta es la parte que no depende del pipeline. Alguien con `kubectl` puede
> saltarse CI entero; no puede saltarse esto. Y fijate que la imagen es nginx
> oficial, perfectamente sana: la rechaza por su procedencia, no por su
> contenido.

## Paso 4 — La imagen firmada, admitida (2 minutos)

```powershell
.\demo.ps1 deploy
curl http://localhost:8080/health
```

> La misma política que rechazó la anterior admite esta, porque tiene una firma
> cosign emitida por el workflow de este repositorio. Keyless: la identidad del
> workflow es la clave, así que no hay material privado que rotar ni filtrar.
> Kyverno además reescribe el tag al digest verificado, así que lo que quedó
> corriendo está pinneado a un digest inmutable.

## Paso 5 — El mismo control en GCP (2 minutos)

```powershell
make tf-validate     # o abrí terraform/modules/binary-authorization/main.tf
```

> En Cashea esto es Binary Authorization sobre Cloud Run, y no tiene costo de
> licencia: se puede encender con la infraestructura de hoy sin esperar GKE. El
> Terraform está escrito y validado; lo único que falta para aplicarlo es un
> proyecto con facturación activa.
>
> Un detalle que es fácil de errar: Binary Authorization no lee firmas de
> Sigstore. Verifica occurrences de Container Analysis firmadas con KMS. Por
> eso el pipeline produce las dos cosas. Si alguien arma esto asumiendo que
> cosign alcanza, la política termina rechazando todas las imágenes.

## Si algo falla en vivo

**El clúster no levanta.** Pasá a los pasos 1, 2 y 5, que no necesitan Docker.
El gate y el Terraform son el 70% del contenido.

**La imagen todavía no está firmada.** `deploy` va a ser rechazado. Decilo
antes: "acá el control me está frenando a mí, que es exactamente para lo que
está". Y mostrá `deny`, que no depende de eso.

**Kyverno tarda.** El `kubectl wait` tiene 300 segundos de timeout. Si se
pasa, seguí con el paso 5 y volvé después.

## Lo que te van a preguntar

**¿Y si el squad necesita desplegar urgente?** La excepción se aprueba por PR
en minutos y vence en 90 días como máximo. Un break-glass sin fecha de
vencimiento es una decisión permanente disfrazada de urgencia.

**¿Esto no frena a los equipos?** El repo arranca en `preview`, que mide sin
bloquear. El número de "cuántos merges se habrían bloqueado" existe antes de
encender enforce, así que la discusión se hace con un dato y no con una
sensación.

**¿Por qué Kyverno y no Binary Authorization?** Por la cuenta de GCP, y lo digo
sin vueltas. El mecanismo es el mismo y el Terraform del camino real está en el
repo.
