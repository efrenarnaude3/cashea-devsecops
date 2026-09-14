# Probar el Terraform en un proyecto GCP real, sin tarjeta

Este documento existe porque el stack de `terraform/` está validado y escaneado
pero nunca se aplicó: la cuenta usada para escribirlo no tiene facturación
activa, y aplicarlo en un proyecto personal no diría nada sobre el entorno
destino.

Acá está el camino para probarlo sin cuenta de facturación: un proyecto temporal
de **Google Cloud Skills Boost**, que se obtiene con la membresía gratuita de
**Google Cloud Innovators** (35 créditos de aprendizaje por mes, sin tarjeta).

## Lo que este camino prueba y lo que no

**Prueba:** que el Terraform resuelve contra las APIs reales de GCP, que los
recursos se crean, y que Binary Authorization rechaza un deploy sin attestation
dejando el rechazo en el audit log.

**No prueba nada sobre el entorno destino.** Un proyecto de laboratorio no tiene
las identidades, las políticas de organización ni el egress de red de la
organización real. El primer `apply` con valor operativo es en un proyecto
sandbox de la organización, y eso es lo que el piloto pide en su primera semana.

Dicho de otra forma: esto quita el riesgo técnico del `apply`, no la necesidad
del sandbox.

---

## Antes de empezar

- [ ] Membresía de Google Cloud Innovators activa (gratuita, sin tarjeta).
- [ ] Un lab de Skills Boost que entregue un proyecto con permisos amplios y
      Cloud Shell. Los labs de infraestructura general suelen servir; los muy
      guiados a veces restringen qué APIs se pueden habilitar.
- [ ] El repo a mano. Cloud Shell trae `git`, `gcloud` y `terraform`.

**El proyecto se destruye al terminar el lab.** Todo lo que quieras conservar
son capturas o la salida de consola copiada, tomadas mientras el lab corre.

---

## Criterio de corte

Cada tramo tiene su propia salida. Si uno falla, quedate con lo que ya
conseguiste y no sigas: los tramos valen por separado.

| Tramo | Tiempo | Qué te queda |
|---|---|---|
| 1 — `plan` contra APIs reales | ~10 min | El plan completo, con la cuenta de recursos |
| 2 — `apply` del attestor y la política | ~20 min | Los recursos creados en un proyecto real |
| 3 — un deploy rechazado | ~10 min | El rechazo de Binary Authorization y su audit log |

Si el tramo 1 falla por permisos del lab, **abandoná**. No hay forma de
arreglarlo desde afuera y no vale más tiempo.

---

## Tramo 1 — Que el plan resuelva contra GCP de verdad

Esto es más valioso de lo que parece. `terraform validate` solo chequea
sintaxis y tipos; un `plan` autenticado resuelve los esquemas de los providers,
los data sources y las referencias de IAM contra la API real.

```bash
PROJECT_ID=$(gcloud config get-value project)
echo "Proyecto del lab: ${PROJECT_ID}"

gcloud services enable \
  artifactregistry.googleapis.com \
  binaryauthorization.googleapis.com \
  cloudkms.googleapis.com \
  cloudresourcemanager.googleapis.com \
  containeranalysis.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  run.googleapis.com \
  sts.googleapis.com
```

**Punto de corte.** Si `gcloud services enable` falla en
`binaryauthorization` o `cloudkms`, el lab no te lo permite. Abandoná acá.

```bash
git clone https://github.com/efrenarnaude3/cashea-devsecops.git
cd cashea-devsecops

cat > terraform/terraform.tfvars <<EOF
project_id        = "${PROJECT_ID}"
github_repository = "efrenarnaude3/cashea-devsecops"
# Una imagen pública cualquiera: el servicio solo tiene que existir para que
# la política tenga a quién rechazar. No es la imagen del pipeline.
image             = "us-docker.pkg.dev/cloudrun/container/hello"
# El default sale por load balancer, que en un lab no vas a tener.
ingress           = "INGRESS_TRAFFIC_ALL"
EOF

terraform -chdir=terraform init
terraform -chdir=terraform plan
```

Guardá la captura del resumen: `Plan: N to add, 0 to change, 0 to destroy`.

> Lo que esto demuestra: el IaC no es un ejercicio de sintaxis. Los data
> sources, los bindings de IAM y los esquemas de los providers resuelven contra
> las APIs reales.

---

## Tramo 2 — Crear el attestor y la política

```bash
terraform -chdir=terraform apply
```

Si falla por un permiso puntual, aplicá solo lo que importa para el tramo 3:

```bash
terraform -chdir=terraform apply \
  -target=module.binary_authorization \
  -target=module.cloud_run
```

Verificá en la API, no en el output de Terraform:

```bash
gcloud container binauthz attestors list
gcloud container binauthz policy export
```

Capturá la política exportada. Ahí se ve `REQUIRE_ATTESTATION` y
`ENFORCED_BLOCK_AND_AUDIT_LOG` en texto plano, que es la evidencia de que el
control está en modo bloqueante y deja rastro.

> Si `prevent_destroy` en la clave KMS te estorba al desarmar, no lo toques: el
> proyecto del lab se destruye solo. Ese `true` está ahí a propósito y Checkov
> tiene razón en exigirlo.

---

## Tramo 3 — El deploy rechazado, que es el artefacto que importa

Esta es la celda "0 de 0 deploys bloqueados" con un numerador.

```bash
gcloud run deploy notes-api-prueba \
  --image us-docker.pkg.dev/cloudrun/container/hello \
  --region us-central1 \
  --allow-unauthenticated
```

Tiene que **fallar**. La imagen es legítima y de Google, pero no tiene una
attestation del attestor que la política exige. Capturá el error completo.

Y después el audit log, que es la mitad que nadie muestra:

```bash
gcloud logging read \
  'protoPayload.serviceName="run.googleapis.com" AND severity>=WARNING' \
  --limit 5 --format json
```

> El rechazo por sí solo es una anécdota. El rechazo **con su entrada en el
> audit log** es lo que hace posible alertar, medir y reportar un porcentaje.
> Es la diferencia entre un control y un control operable.

---

## Qué conservar

1. El resumen del `plan`.
2. La política exportada con `REQUIRE_ATTESTATION`.
3. El error del `gcloud run deploy` rechazado.
4. La entrada del audit log.

Cuatro capturas. Con eso, la afirmación "el mecanismo es el mismo en GCP" deja
de apoyarse solo en el Terraform y pasa a apoyarse en una corrida.
