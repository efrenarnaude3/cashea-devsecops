# Heimdall — gates y checks en CD

Implementación de referencia del control que decide **qué se puede desplegar**:
una imagen que el pipeline no construyó, escaneó y firmó no llega a correr.

Es la contraparte ejecutable de
[`PLAN-heimdall-security-gates.md`](docs/plan.md): un servicio NestJS sobre
contenedor, un pipeline de GitHub Actions que solo publica lo que aprueba el
gate, y un control de admisión en el clúster que verifica la firma antes de
admitir el Pod.

## El resultado, en una línea

El gate corrió en modo preview sobre este servicio y marcó **7 hallazgos
bloqueantes sobre 99 evaluados**. Los 7 son una sola causa, con una excepción
escrita, justificada de forma verificable y con fecha de vencimiento. Después de
eso el repo pasó a `enforce`.

Ese orden —medir, revisar, justificar, encender— es la propuesta. No el gate.

## El demo

Los dos primeros comandos no necesitan Docker, ni red, ni una cuenta de nube:

```powershell
.\demo.ps1 check     # el repo se verifica a sí mismo + self-test del gate
.\demo.ps1 gate      # el gate decide sobre hallazgos de ejemplo
```

```bash
make check           # lo mismo en Linux, macOS o Git Bash
make gate
```

El resto levanta el control de admisión en un clúster local:

```powershell
.\demo.ps1 up -Preload -Owner tu-usuario   # clúster + Kyverno, sin salir a internet
.\demo.ps1 trust                           # solo si tu red intercepta TLS
.\demo.ps1 policy -Owner tu-usuario -Repo tu-repo
.\demo.ps1 deny                            # imagen no autorizada: RECHAZADA
.\demo.ps1 deploy -Owner tu-usuario        # imagen firmada: admitida
curl.exe http://localhost:8080/health
```

`-Preload` baja las imágenes con el Docker del host y las inyecta en el nodo, de
modo que el clúster nunca necesita resolver un registry. `trust` hace falta
detrás de un proxy de inspección TLS —Cloudflare Gateway, Zscaler y similares—,
donde la verificación keyless de Sigstore no puede validar su propia cadena de
confianza. Ambas cosas están explicadas en
[`docs/operacion-en-red-corporativa.md`](docs/operacion-en-red-corporativa.md),
que es además el documento con más hallazgos reutilizables de este repo.

El paso a paso para la reunión está en
[`docs/demo-runbook.md`](docs/demo-runbook.md).

## Qué hay acá

```
service/          Servicio NestJS. Es el artefacto que el pipeline construye,
                  escanea, firma y despliega. No es el objeto del proyecto.
appsec/           El contrato del gate: gate.yaml (modo + fecha de adopción)
                  y exceptions.yaml (excepciones con aprobador y vencimiento)
scripts/gate.py   El motor de decisión. Con self-tests embebidos
scripts/verify_repo.py   Chequeo de coherencia del repo, sin red
policy/           Política de Kyverno: registry autorizado + firma del pipeline
deploy/           Clúster kind y manifiestos con PSS restricted
terraform/        El camino en GCP: Cloud Run + Binary Authorization + WIF
.github/workflows/  ci-security, codeql, secrets-scan, iac-scan
demo/findings/    Hallazgos de ejemplo para mostrar el gate sin escanear nada
docs/             Runbook del demo, camino GCP, operación detrás de un proxy
                  de inspección TLS, y decisiones de diseño
```

## Las tres decisiones que sostienen el diseño

**La imagen no se publica hasta que el gate la aprueba.** El pipeline
construye, escanea y decide *antes* del push al registry. Publicar primero y
escanear después deja una imagen vulnerable en el registry esperando a que
alguien la despliegue.

**Delta gating: el backlog histórico no bloquea.** Cada repo declara su fecha
de adopción en `appsec/gate.yaml`, y el gate solo bloquea hallazgos
posteriores. Es la razón por la que los gates no están encendidos en la
mayoría de las empresas con deuda: si el control bloquea el backlog, el primer
squad pide apagarlo y el control queda apagado con el costo político ya pagado.

**El gate no es un scanner.** Lee lo que Trivy, npm audit, CodeQL y Semgrep ya
produjeron, y decide. Agregar otro scanner habría creado otra fuente de
hallazgos y otro lugar donde mirarlos.

## Las cuatro ramas de la decisión

`.\demo.ps1 gate` las muestra todas sobre el mismo set de hallazgos:

| Hallazgo | Qué decide el gate | Por qué |
|---|---|---|
| CRITICAL nuevo, con fix | **BLOQUEA** | Es accionable hoy y es posterior a la adopción |
| CRITICAL nuevo, con excepción vigente | Pasa | Riesgo aceptado, con aprobador y fecha de revisión |
| HIGH anterior a la adopción | Pasa | Backlog histórico: lo drena el proceso de vulnerabilidades con su SLA |
| HIGH sin fix disponible | Pasa | No hay nada que hacer en este PR; se gestiona por el playbook |
| MEDIUM | Pasa | Se reporta y entra al backlog; no frena el trabajo diario |

Y la excepción vencida vuelve a bloquear sola, sin que nadie tenga que
acordarse de revisarla.

## Códigos de salida del gate

| Código | Significado |
|---|---|
| 0 | La corrida pasa, o el repo está en `preview` (que nunca bloquea) |
| 1 | Bloqueada: hay hallazgos que cumplen todas las condiciones |
| 2 | Error de configuración: una excepción sin aprobador, sin vencimiento o con más de 90 días de vigencia |

El código 2 también dispara en modo preview, a propósito. Una excepción mal
formada no es un hallazgo más: es el control roto, y un control roto no puede
reportar "todo bien".

## Del clúster local a GCP

El control de admisión se demuestra con Kyverno sobre kind porque no depende
de una cuenta de nube con tarjeta. El mecanismo es el mismo que usa Binary
Authorization: verificar la procedencia de la imagen antes de admitirla.

En GCP el equivalente está escrito en `terraform/` y se valida sin
credenciales (`make tf-validate`). Dos datos que importan:

- **Binary Authorization para Cloud Run no tiene cargo.** El control se
  enciende con la infraestructura de hoy, sin esperar la migración a GKE.
- **Binary Authorization no lee firmas de Sigstore.** Verifica occurrences de
  Container Analysis firmadas con una clave KMS. Por eso el pipeline produce
  dos artefactos distintos, y la diferencia está explicada en
  [`docs/gcp-path.md`](docs/gcp-path.md).

## Antes del primer push

```bash
cd service && npm install --package-lock-only   # genera el lockfile
```

Hacelo primero. `npm ci` exige el lockfile, así que sin él fallan el job
`quality`, el job `sca` y el `docker build`. El chequeo offline lo marca como
aviso, no como error: es lo único del repo que no se puede versionar sin
correr una instalación.

## Verificación

```
[PASS] Sintaxis Python          archivos compilan
[PASS] Sintaxis YAML            archivos parsean
[PASS] Cableado de workflows    needs y outputs coherentes
[PASS] Configuración del gate   modo, adopción y excepciones válidas
[PASS] Kubernetes y política    PSS restricted + namespace correcto
[PASS] Terraform                módulos, inputs y formato
[PASS] Versiones y pines        Node coherente, dependencias exactas
[PASS] Lockfile de npm          service/package-lock.json presente
[PASS] Sin secretos hardcodeados

9/9 chequeos pasaron
```

Qué valida cada chequeo y por qué existe está en el docstring de
`scripts/verify_repo.py`. El self-test de `scripts/gate.py` cubre las ramas de
la decisión más el mapeo de severidades de npm audit, y corre sin PyYAML y sin
archivos: verifica la lógica incluso en una máquina limpia.

## Limitaciones conocidas

Se listan acá porque salieron de correr esto sobre datos reales, y porque un
repo de referencia que no dice dónde falla enseña mal.

**El gate no deduplica entre fuentes.** La misma vulnerabilidad llega como GHSA
desde `npm audit` (sin fecha de publicación) y como CVE desde Trivy (con fecha).
Sin fecha, el gate no puede probar que un hallazgo es anterior a la adopción y lo
trata como nuevo, que es el lado seguro del error — pero el efecto es que la
misma vulnerabilidad bloquea o no según quién la reportó.

**`ClusterPolicy` está deprecada.** Kyverno lo avisa al aplicar la política. La
sucesora es `ImageValidatingPolicy`, con CEL.

**La verificación keyless necesita salida a internet** hacia Fulcio, Rekor y el
CDN de TUF. En una red con inspección TLS eso requiere una decisión previa de
arquitectura, no un workaround. En Cloud Run con Binary Authorization el
problema no existe: la verificación es interna a Google Cloud.
