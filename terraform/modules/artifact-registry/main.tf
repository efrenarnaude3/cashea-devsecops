variable "project_id" {
  description = "Proyecto GCP."
  type        = string
}

variable "region" {
  description = "Región del repositorio."
  type        = string
}

variable "labels" {
  description = "Labels operativos."
  type        = map(string)
  default     = {}
}

resource "google_artifact_registry_repository" "repo" {
  project       = var.project_id
  location      = var.region
  repository_id = "heimdall"
  format        = "DOCKER"
  description   = "Imágenes producidas y firmadas por el pipeline de Heimdall"
  labels        = var.labels

  docker_config {
    # Un tag publicado no se puede repuntar a otra imagen. Sin esto, "la
    # imagen que verificamos" y "la imagen que corre" pueden divergir sin que
    # cambie nada visible.
    immutable_tags = true
  }

  # La retención necesita las dos mitades. Una policy KEEP sola es solo una
  # exención frente a las policies DELETE: sin una regla DELETE no borra nada,
  # y el free tier de 0,5 GB se llena en unos pocos builds.
  cleanup_policies {
    id     = "keep-recent-versions"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-old-versions"
    action = "DELETE"

    condition {
      tag_state  = "ANY"
      older_than = "2592000s" # 30 días
    }
  }
}

output "repository_id" {
  description = "ID del repositorio."
  value       = google_artifact_registry_repository.repo.repository_id
}

output "repository_url" {
  description = "Ruta completa para docker push."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}"
}
