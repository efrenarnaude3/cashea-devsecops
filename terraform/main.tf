# El camino en GCP: el mismo control que Kyverno aplica en el clúster local,
# expresado con los productos que Cashea ya usa.
#
# Binary Authorization para Cloud Run no tiene cargo, así que este control se
# puede encender con la infraestructura de hoy, sin esperar la migración a GKE.
# Cuando los servicios migren, la política y el attestor son los mismos: cambia
# el destino del deploy, no el control.
#
# Lo que este stack NO habilita, a propósito: containerscanning.googleapis.com.
# El Artifact Analysis de GCP cobra USD 0.26 por imagen escaneada y escanea
# después de publicar. El escaneo lo hace Trivy en CI, gratis y antes de
# publicar, que es donde el gate lo necesita.

locals {
  required_services = [
    "artifactregistry.googleapis.com",
    "binaryauthorization.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "containeranalysis.googleapis.com", # attestations, NO escaneo
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "run.googleapis.com",
    "sts.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = toset(local.required_services)

  project = var.project_id
  service = each.value

  # Deshabilitar una API compartida al destruir este stack puede romper
  # recursos ajenos en el mismo proyecto.
  disable_on_destroy = false
}

module "artifact_registry" {
  source = "./modules/artifact-registry"

  project_id = var.project_id
  region     = var.region
  labels     = var.labels

  depends_on = [google_project_service.required]
}

module "binary_authorization" {
  source = "./modules/binary-authorization"

  project_id               = var.project_id
  ci_service_account_email = google_service_account.ci.email

  depends_on = [google_project_service.required]
}

module "cloud_run" {
  source = "./modules/cloud-run"

  project_id   = var.project_id
  region       = var.region
  service_name = var.service_name
  image        = var.image
  ingress      = var.ingress
  labels       = var.labels

  depends_on = [google_project_service.required]
}

# --- Identidades -----------------------------------------------------------
# Una service account por etapa. CI publica y atesta, pero no despliega. CD
# despliega, pero no puede publicar imágenes. Ninguna tiene archivo de clave:
# las dos se impersonan desde el token OIDC de GitHub Actions.

resource "google_service_account" "ci" {
  project      = var.project_id
  account_id   = "heimdall-ci"
  display_name = "CI: publica y atesta imágenes"
}

resource "google_service_account" "cd" {
  project      = var.project_id
  account_id   = "heimdall-cd"
  display_name = "CD: despliega en Cloud Run"
}

resource "google_artifact_registry_repository_iam_member" "ci_writer" {
  project    = var.project_id
  location   = var.region
  repository = module.artifact_registry.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.ci.email}"
}

# `gcloud container binauthz attestations sign-and-create` necesita tres cosas
# y si falta una, el pipeline no puede atestar y la política termina
# rechazando todo: leer el attestor, firmar con su clave KMS (se otorga en el
# módulo) y crear la occurrence.
resource "google_project_iam_member" "ci_attestor_viewer" {
  project = var.project_id
  role    = "roles/binaryauthorization.attestorsViewer"
  member  = "serviceAccount:${google_service_account.ci.email}"
}

resource "google_project_iam_member" "ci_occurrences_editor" {
  project = var.project_id
  role    = "roles/containeranalysis.occurrences.editor"
  member  = "serviceAccount:${google_service_account.ci.email}"
}

resource "google_cloud_run_v2_service_iam_member" "cd_developer" {
  project  = var.project_id
  location = var.region
  name     = module.cloud_run.service_name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.cd.email}"
}

# El runtime del servicio corre con su propia identidad, no con la default de
# Compute Engine, que arrastra permisos de editor del proyecto.
resource "google_service_account_iam_member" "cd_can_use_runtime_sa" {
  service_account_id = module.cloud_run.runtime_service_account_id
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.cd.email}"
}

# --- Workload Identity Federation: OIDC de GitHub -> credenciales cortas ----

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "github-actions-pool"
  display_name              = "GitHub Actions"

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions-provider"
  display_name                       = "GitHub Actions OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # Sin esta condición, CUALQUIER repositorio de GitHub del mundo podría
  # cambiar su token OIDC por credenciales de este proyecto. Es la línea que
  # separa federación de puerta abierta.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "ci_wif" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

resource "google_service_account_iam_member" "cd_wif" {
  service_account_id = google_service_account.cd.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}
