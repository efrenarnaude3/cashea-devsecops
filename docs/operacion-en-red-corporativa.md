# Correr control de admisión detrás de un gateway que intercepta TLS

Este documento existe porque armar el demo en una laptop corporativa produjo un
hallazgo que vale más que el demo: **la verificación keyless de Sigstore no
funciona detrás de un gateway de inspección TLS sin una decisión explícita de
arquitectura.**

No es una particularidad de esta máquina. Es lo que va a pasar en cualquier
clúster de Cashea que corra detrás del mismo gateway.

---

## El hallazgo

La laptop tiene **Cloudflare Zero Trust Gateway**. Se ve en la cadena de
certificados de cualquier conexión saliente:

```
CN=Gateway CA - Cloudflare Managed G1 37055fa17852af020dcb44e94be720ec
O="Cloudflare, Inc."
```

El gateway termina la conexión TLS, la inspecciona y la vuelve a firmar con su
propia CA. Windows tiene esa CA instalada, así que el navegador, `git` y
`docker` funcionan sin quejarse. **Todo lo que corre adentro de un contenedor,
no**: cada imagen trae su propio bundle de certificados y ninguno la conoce.

El síntoma es siempre el mismo y no menciona al gateway:

```
x509: certificate signed by unknown authority
```

### Dónde pega, en orden de aparición

| Componente | Qué intenta | Resultado sin intervención |
|---|---|---|
| containerd del nodo | bajar imágenes de cualquier registry | `ImagePullBackOff` |
| Kyverno (admission) | bajar las raíces TUF de Sigstore | rechaza **toda** imagen |
| Kyverno (admission) | leer la firma cosign del registry | rechaza **toda** imagen |
| kubelet | resolver la imagen pineada al digest | `ImagePullBackOff` |

El segundo y el tercero son los importantes. Kyverno falla **cerrado**: ante una
cadena de confianza que no puede validar, no admite nada. Es el comportamiento
correcto, y también significa que un gateway mal contemplado convierte un
control de seguridad en una caída total de los despliegues.

---

## Lo que implica para Cashea

**Encender verificación de firmas en un clúster detrás del gateway requiere
decidir una de estas tres cosas, antes de encenderlo:**

1. **Excluir del gateway los endpoints de Sigstore y del registry.**
   `tuf-repo-cdn.sigstore.dev`, `fulcio.sigstore.dev`, `rekor.sigstore.dev` y el
   registry de imágenes. Es lo más limpio: nadie tiene que confiar en el
   interceptor. Requiere una regla de red y un dueño que la mantenga.

2. **Distribuir la CA del gateway a los workloads que verifican firmas.**
   Funciona, y es lo que hace el `trust` de este repo. El costo es explícito:
   el workload pasa a confiar en que el gateway no altera lo que le entrega.
   Para un verificador de firmas, esa confianza no es menor y merece quedar
   escrita en algún lado, no resuelta en un script.

3. **Verificar con clave en vez de keyless.** Elimina la dependencia de Fulcio y
   Rekor, pero no la del registry, y reintroduce material privado que hay que
   rotar y custodiar. Es un intercambio, no una solución.

**En Cloud Run con Binary Authorization el problema no existe**, y vale la pena
decirlo porque cambia la recomendación. Binary Authorization no consulta a
Sigstore: verifica occurrences de Container Analysis firmadas con una clave de
KMS, todo adentro de Google Cloud. El camino que este repo propone para Cashea
es, además de gratuito, el que no choca con el gateway.

---

## Los seis problemas, y cómo se resolvió cada uno

Están documentados en el código, en el lugar donde importan. Acá está el índice.

### 1. El CRD de Kyverno no entra con `kubectl apply`

```
CustomResourceDefinition "clusterpolicies.kyverno.io" is invalid:
metadata.annotations: Too long: may not be more than 262144 bytes
```

`kubectl apply` guarda una copia del manifiesto en la anotación
`last-applied-configuration`. El CRD de ClusterPolicy pesa más que el límite de
256 KiB de una anotación. El resto del manifiesto **sí se aplica**, así que
queda una instalación a medias y el error aparece cuatro comandos después, como
`no matches for kind "ClusterPolicy"`.

→ `kubectl apply --server-side --force-conflicts`. Con server-side apply el
estado deseado lo lleva el API server en `managedFields`.

### 2. La versión del nodo no estaba fijada

`kind create cluster` sin `image` usa el nodo más nuevo que trae el binario. Ese
número se mueve solo cuando kind publica una versión, y Kyverno v1.19 soporta
Kubernetes v1.33 a v1.35. Fuera de esa ventana los pods no llegan a Ready y el
error es un timeout mudo.

→ `image: kindest/node:v1.34.0` fijado en `deploy/kind/cluster.yaml`, con un
comentario que ata esa línea a la versión de Kyverno. Un demo cuya
reproducibilidad depende del `latest` de otro proyecto no es reproducible.

### 3. `ctr import --all-platforms` y los manifiestos de attestation

```
ctr: content digest sha256:7693fcba...: not found
```

`kind load docker-image` importa con `--all-platforms`, que exige que estén
presentes todos los manifiestos que el índice menciona. Las imágenes publicadas
con buildx incluyen manifiestos de attestation —provenance y SBOM, justamente
los artefactos de cadena de suministro— que Docker no baja al resolver una sola
plataforma.

→ Import manual con `ctr images import --digests`, sin `--all-platforms`.

### 4. `docker cp` contra un tmpfs

```
Successfully copied 52.3MB to heimdall-control-plane:/tmp/image-load.tar
ctr: open /tmp/image-load.tar: no such file or directory
```

Las dos líneas son ciertas. kind monta un tmpfs sobre `/tmp`; `docker cp`
escribe en la capa del contenedor, que el montaje tapa.

→ `/var/tmp`.

### 5. JSON merge patch borra las listas

```
The Deployment "kyverno-admission-controller" is invalid:
spec.template.spec.containers[0].image: Required value
```

`--type=merge` reemplaza las listas enteras: un parche que declara un contenedor
con `name` y `volumeMounts` borra `image` y todo lo demás.

→ `--type=strategic`, que conoce las claves de mezcla de los tipos nativos y
fusiona por elemento.

### 6. La imagen precargada no se encuentra cuando la política pinea el digest

Kyverno reescribe la referencia al digest verificado (`mutateDigest`). containerd
busca por el string exacto de la referencia, y `repo:tag@sha256:...` no es el
nombre con el que se importó la imagen. Sale a resolverlo al registry y vuelve a
chocar con el gateway. El síntoma desorienta: la imagen está en el nodo y el
error dice `ImagePullBackOff`.

→ Registrar también las formas con digest (`ctr images tag`) durante la
precarga. Es lo que permite que un clúster air-gapped conviva con una política
que pinea digests, sin renunciar a ninguna de las dos cosas.

---

## Lo que queda para el piloto

- Decidir cuál de las tres opciones de arriba adopta Cashea, y escribirla.
- Migrar `ClusterPolicy` a `ImageValidatingPolicy` (CEL). Kyverno ya avisa que
  la primera está deprecada.
- Deduplicar hallazgos entre fuentes: las mismas vulnerabilidades llegan como
  GHSA desde npm audit (sin fecha) y como CVE desde Trivy (con fecha), y el
  gate las trata distinto según quién las reportó.
