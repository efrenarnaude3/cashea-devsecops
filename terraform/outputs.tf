# Cada output mapea a una variable de repositorio en GitHub. `terraform output`
# es la checklist de configuración del pipeline.

output "artifact_registry_repository" {
  description = "Repositorio de imágenes."
  value       = module.artifact_registry.repository_id
}

output "cloud_run_service" {
  description = "Servicio de Cloud Run desplegado."
  value       = module.cloud_run.service_name
}

output "cloud_run_url" {
  description = "URL del servicio. Con ingress interno, solo responde detrás del load balancer."
  value       = module.cloud_run.service_url
}

output "binauthz_attestor" {
  description = "Variable BINAUTHZ_ATTESTOR."
  value       = module.binary_authorization.attestor_name
}

output "binauthz_key_version" {
  description = "Variable BINAUTHZ_KEY_VERSION. Nombre relativo del recurso, que es la forma que acepta `gcloud container binauthz attestations sign-and-create --keyversion`."
  value       = module.binary_authorization.signing_key_version
}

output "ci_service_account" {
  description = "Variable CI_SERVICE_ACCOUNT."
  value       = google_service_account.ci.email
}

output "cd_service_account" {
  description = "Variable CD_SERVICE_ACCOUNT."
  value       = google_service_account.cd.email
}

output "workload_identity_provider" {
  description = "Variable WIF_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.github.name
}
