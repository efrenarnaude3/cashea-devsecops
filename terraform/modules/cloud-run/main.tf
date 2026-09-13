variable "project_id" {
  description = "Proyecto GCP."
  type        = string
}

variable "region" {
  description = "Región del servicio."
  type        = string
}

variable "service_name" {
  description = "Nombre del servicio."
  type        = string
}

variable "image" {
  description = "Imagen a desplegar, por digest."
  type        = string
}

variable "ingress" {
  description = "Política de ingress del servicio."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
}

variable "labels" {
  description = "Labels operativos."
  type        = map(string)
  default     = {}
}

# Identidad propia del runtime. La default de Compute Engine arrastra permisos
# de editor del proyecto: si el servicio se compromete, se lleva el proyecto.
resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = "${var.service_name}-runtime"
  display_name = "Runtime de ${var.service_name}: sin permisos más allá de logging"
}

resource "google_cloud_run_v2_service" "service" {
  project  = var.project_id
  name     = var.service_name
  location = var.region
  ingress  = var.ingress
  labels   = var.labels

  template {
    service_account = google_service_account.runtime.email

    scaling {
      # min 0: sin tráfico no hay instancias y no hay cargo. El free tier de
      # Cloud Run no cobra CPU ni memoria en idle si no hay min instances.
      min_instance_count = 0
      max_instance_count = 4
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      startup_probe {
        http_get {
          path = "/health/ready"
          port = 8080
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 6
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        period_seconds = 30
      }
    }
  }

  # Le pide a Cloud Run que evalúe la política de Binary Authorization del
  # proyecto en cada deploy. Es la línea que conecta este servicio con el
  # módulo binary-authorization.
  binary_authorization {
    use_default = true
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

# Sin binding a allUsers: el servicio no es público. Quien lo invoque necesita
# IAM, y el tráfico de internet entra por el load balancer con Cloud Armor.

output "service_name" {
  description = "Nombre del servicio."
  value       = google_cloud_run_v2_service.service.name
}

output "service_url" {
  description = "URL del servicio."
  value       = google_cloud_run_v2_service.service.uri
}

output "runtime_service_account_id" {
  description = "ID de la service account del runtime."
  value       = google_service_account.runtime.id
}
