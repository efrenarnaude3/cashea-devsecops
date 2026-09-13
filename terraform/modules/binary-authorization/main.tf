# Binary Authorization: el control del lado del clúster que hace que el gate de
# CI no se pueda esquivar. Alguien con permisos de deploy puede saltarse el
# pipeline; no puede saltarse esto.
#
# Detalle que conviene saber antes de una entrevista: Binary Authorization NO
# lee firmas de Sigstore. Verifica occurrences de Container Analysis firmadas
# con la clave KMS registrada en el attestor. Por eso el pipeline produce dos
# artefactos distintos: `cosign` para verificación pública de supply chain, y
# `gcloud container binauthz attestations sign-and-create` para la admisión.
# Asumir que cosign alcanza es el error más común de esta arquitectura, y su
# síntoma es que la política rechaza absolutamente todas las imágenes.

variable "project_id" {
  description = "Proyecto GCP."
  type        = string
}

variable "ci_service_account_email" {
  description = "Identidad de CI que crea las attestations. Necesita notes.attacher sobre la note y signerVerifier sobre la clave."
  type        = string
}

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_kms_key_ring" "attestor" {
  project  = var.project_id
  name     = "binauthz-attestor-keyring"
  location = "global"
}

resource "google_kms_crypto_key" "attestor" {
  name     = "binauthz-attestor-key"
  key_ring = google_kms_key_ring.attestor.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }

  lifecycle {
    # Borrar una clave que firmó attestations vivas las invalida a todas, y
    # deja de golpe a todas las imágenes ya desplegadas sin poder demostrar su
    # procedencia. Por eso va en true.
    #
    # Lo tenía en false por comodidad, para poder destruir un sandbox, y
    # Checkov lo marcó con CKV_GCP_82. Tenía razón: "es un demo" no es una
    # razón de seguridad, y un repo de referencia no debería enseñar el valor
    # inseguro. Para desarmar un entorno de prueba, el camino es un commit que
    # lo ponga en false a propósito, que queda revisable en un PR.
    #
    # Está hardcodeado porque Terraform no acepta variables dentro de
    # `lifecycle`: el bloque se evalúa antes de que se conozcan los valores.
    prevent_destroy = true
  }
}

# El attestor registra la mitad PÚBLICA de la clave. Leerla del key version, en
# vez de pegar un PEM, evita que el valor se desincronice de la clave real.
data "google_kms_crypto_key_version" "attestor" {
  crypto_key = google_kms_crypto_key.attestor.id
  version    = 1
}

resource "google_container_analysis_note" "attestor" {
  project = var.project_id
  name    = "heimdall-attestor-note"

  attestation_authority {
    hint {
      human_readable_name = "Heimdall pipeline attestor"
    }
  }
}

# Dos bindings que es fácil olvidar y que rompen la admisión en silencio: CI
# tiene que poder adjuntar occurrences a la note, y el service agent de Binary
# Authorization tiene que poder leerlas para verificarlas.
resource "google_container_analysis_note_iam_member" "ci_attacher" {
  project = var.project_id
  note    = google_container_analysis_note.attestor.name
  role    = "roles/containeranalysis.notes.attacher"
  member  = "serviceAccount:${var.ci_service_account_email}"
}

resource "google_container_analysis_note_iam_member" "binauthz_viewer" {
  project = var.project_id
  note    = google_container_analysis_note.attestor.name
  role    = "roles/containeranalysis.notes.occurrences.viewer"
  member  = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-binaryauthorization.iam.gserviceaccount.com"
}

# CI firma con la clave; nunca puede administrarla.
resource "google_kms_crypto_key_iam_member" "ci_signer" {
  crypto_key_id = google_kms_crypto_key.attestor.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${var.ci_service_account_email}"
}

resource "google_binary_authorization_attestor" "attestor" {
  project = var.project_id
  name    = "heimdall-attestor"

  attestation_authority_note {
    note_reference = google_container_analysis_note.attestor.name

    public_keys {
      # El `id` del data source ya viene en la forma URI
      # //cloudkms.googleapis.com/v1/... que Binary Authorization usa para
      # matchear. Agregarle el prefijo a mano lo duplica y la verificación
      # falla siempre, en silencio.
      id = data.google_kms_crypto_key_version.attestor.id

      pkix_public_key {
        # Los dos valores salen de la clave. Hardcodear el algoritmo genera un
        # diff permanente: KMS y Binary Authorization escriben la misma curva
        # con nombres distintos.
        public_key_pem      = data.google_kms_crypto_key_version.attestor.public_key[0].pem
        signature_algorithm = data.google_kms_crypto_key_version.attestor.public_key[0].algorithm
      }
    }
  }
}

resource "google_binary_authorization_policy" "policy" {
  project = var.project_id

  # Deniega por defecto. El modo de enforcement también escribe los deploys
  # bloqueados al audit log, que es lo que hace posible alertar y lo que
  # convierte la celda "0 de 0 deploys bloqueados" en un número real.
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"

    require_attestations_by = [google_binary_authorization_attestor.attestor.name]
  }

  # Las imágenes de sistema de Google no llevan attestation nuestra. Sin esta
  # exención, el proyecto no puede correr ni sus propios componentes.
  global_policy_evaluation_mode = "ENABLE"
}

output "attestor_id" {
  description = "ID del attestor."
  value       = google_binary_authorization_attestor.attestor.id
}

output "attestor_name" {
  description = "Nombre del attestor, como lo referencian las reglas de admisión."
  value       = google_binary_authorization_attestor.attestor.name
}

output "signing_key_version" {
  description = "Key version que firma las attestations, en la forma projects/.../cryptoKeyVersions/N que acepta gcloud."
  value       = data.google_kms_crypto_key_version.attestor.name
}
