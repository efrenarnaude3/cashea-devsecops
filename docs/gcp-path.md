# El camino en GCP

El demo corre sobre kind con Kyverno. En GCP el mismo control se arma con
Cloud Run y Binary Authorization, y el Terraform está en `terraform/`. Este
documento explica qué cambia, qué no, y el error que casi todo el mundo comete
al implementarlo.

## Qué está verificado y qué no

Va primero y sin adornos, porque un repo de referencia que deja esto ambiguo
hace perder tiempo a quien lo lee.

| | Estado |
|---|---|
| Sintaxis y consistencia del Terraform (`fmt`, `validate`) | **Verificado en CI** |
| Política de seguridad del IaC (Checkov, tfsec) | **Verificado en CI** |
| El control de admisión, corriendo y rechazando | **Verificado**, sobre Kyverno en kind |
| `terraform apply` sobre un proyecto real | **No ejecutado** |
| Binary Authorization rechazando un deploy en Cloud Run | **No ejecutado** |

`terraform apply` necesita un proyecto GCP con facturación activa, y este stack
se escribió sin uno.

**Aplicarlo en un proyecto personal tampoco habría probado gran cosa.** Un
attestor y una policy en una cuenta ajena a la organización no dicen nada sobre
cómo se comporta el control en el entorno de Cashea: ni las identidades, ni las
políticas de la organización, ni el egress de red son los mismos. El lugar
correcto para el primer `apply` es un proyecto sandbox de la organización, y eso
es exactamente lo que el piloto pide en su primera semana.

Lo que sí se puede afirmar hoy, y es la parte que importa: **el mecanismo está
demostrado, incluido el que hace distinto a Binary Authorization**.

`policy/require-gate-attestation.yaml` no verifica una firma: exige un
**atestado** firmado por el pipeline que declare que el gate corrió en modo
enforce y no dejó pasar nada bloqueante, y evalúa ese contenido antes de
admitir. Esa es la forma exacta en que funciona Binary Authorization —una
identidad registrada afirma algo sobre la imagen, la política exige esa
afirmación—, y acá se ve corriendo.

Lo que falta es trasladarlo del clúster local al proveedor, que es trabajo de
configuración sobre un control ya probado, no una incógnita de diseño.

## Qué es equivalente y qué no

| Pieza | En el demo (kind) | En GCP |
|---|---|---|
| Runtime | Pod en kind | Cloud Run |
| Registry | ghcr.io | Artifact Registry |
| Firma | cosign keyless (Sigstore) | cosign keyless **más** attestation de Container Analysis |
| Atestación del veredicto | Predicado in-toto firmado, verificado por Kyverno | Occurrence de Container Analysis firmada con KMS |
| Admisión | Kyverno `verifyImages` | Binary Authorization |
| Política | ClusterPolicy en el clúster | Policy a nivel proyecto |
| Evidencia de rechazo | Evento del API server | Audit log de GCP |

El contrato del contenedor es idéntico: escuchar en `$PORT` y bindear 0.0.0.0.
El mismo binario y la misma imagen corren en los dos lados sin tocar una línea.

## El error que rompe esta arquitectura

**Binary Authorization no lee firmas de Sigstore.**

Es lo que más se asume mal, porque las dos cosas se llaman "firmar la imagen".
Binary Authorization verifica *occurrences de Container Analysis* firmadas con
la clave KMS registrada en el attestor. Una firma de cosign, por más válida que
sea, no le dice nada.

El síntoma cuando se implementa asumiendo lo contrario: la política rechaza
absolutamente todas las imágenes, incluidas las que el pipeline firmó, y el
mensaje de error no menciona a Sigstore por ningún lado.

Por eso el pipeline produce dos artefactos distintos, y cada uno responde a un
verificador distinto:

- **cosign keyless** escribe una firma y una attestation del SBOM en el
  registry. Cualquiera la puede verificar contra el transparency log público,
  sin claves compartidas. Es el artefacto de supply chain, y es lo que Kyverno
  verifica en el clúster.
- **`gcloud container binauthz attestations sign-and-create`** crea la
  occurrence firmada con KMS que Binary Authorization sí verifica. Es el
  artefacto de admisión.

## Costo

Binary Authorization **para Cloud Run no tiene cargo**. En GKE son USD 0.01613
por clúster por hora, con un crédito mensual de USD 12 por cuenta de
facturación.

Lo que sí cuesta y este stack no habilita a propósito:

- **Container Scanning API (Artifact Analysis)**: USD 0.26 por imagen
  escaneada, y escanea *después* de publicar. El escaneo lo hace Trivy en CI,
  gratis y antes de publicar, que es donde el gate lo necesita.
  `scripts/verify_repo.py` falla si alguien lo agrega al Terraform.
- **Cloud KMS**: USD 0.06 por versión de clave por mes, más USD 0.03 cada
  10.000 operaciones de firma. Es el único costo fijo del control, y son
  centavos por trimestre.

## Los tres permisos que se olvidan

`gcloud container binauthz attestations sign-and-create` necesita las tres
cosas, y si falta una, el pipeline no puede atestar y la política termina
rechazando todo:

1. `roles/binaryauthorization.attestorsViewer` sobre el proyecto, para leer el
   attestor.
2. `roles/containeranalysis.notes.attacher` sobre la note, para adjuntar la
   occurrence.
3. `roles/cloudkms.signerVerifier` sobre la clave, para firmarla.

Hay un cuarto que también es fácil de perder: el service agent de Binary
Authorization (`service-<project-number>@gcp-sa-binaryauthorization.iam...`)
necesita `roles/containeranalysis.notes.occurrences.viewer` para poder leer lo
que va a verificar. Sin eso, la verificación falla del lado del verificador.

Los cuatro están en `terraform/modules/binary-authorization/main.tf`.

## Cuando llegue GKE

No cambia el control, cambia el destino. La misma policy y el mismo attestor
aplican a un clúster de GKE con `binary_authorization.evaluation_mode =
PROJECT_SINGLETON_POLICY_ENFORCE`. Lo que se agrega en GKE, y en Cloud Run no
aplica, es el resto del hardening del clúster: nodos privados con Private
Google Access, Workload Identity, Dataplane V2 para NetworkPolicy, Pod Security
Admission.

Dicho de otra forma: el trabajo que se hace hoy sobre Cloud Run no se tira
cuando llegue la migración.

## Para aplicarlo de verdad

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars   # editar
terraform -chdir=terraform init
terraform -chdir=terraform plan
```

Hace falta un proyecto GCP con facturación activa. El nivel Always Free alcanza
de sobra para el piloto: Cloud Run da 2 millones de requests, 180.000
vCPU-segundos y 360.000 GiB-segundos por mes, y sin instancias mínimas no hay
cargo cuando el servicio está idle. Artifact Registry da 0,5 GB, que son unas
pocas imágenes distroless: por eso el módulo incluye una cleanup policy con las
dos mitades, KEEP y DELETE. Una policy KEEP sola no borra nada.
