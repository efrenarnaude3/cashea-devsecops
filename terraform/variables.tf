variable "project_id" {
  description = "Proyecto GCP dedicado al piloto. Nunca uno productivo."
  type        = string
}

variable "region" {
  description = "Región de Cloud Run y de Artifact Registry."
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Nombre del servicio de Cloud Run."
  type        = string
  default     = "notes-api"
}

variable "image" {
  description = "Imagen a desplegar, referenciada por digest. Un tag es mutable: lo que se admitió ayer puede no ser lo que corre hoy."
  type        = string
  default     = "us-central1-docker.pkg.dev/PROJECT/heimdall/notes-api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

variable "github_repository" {
  description = "owner/repo autorizado a impersonar las service accounts vía Workload Identity Federation. Solo este repo puede publicar y desplegar."
  type        = string

  # El formato importa: de acá salen la condición del provider OIDC y el
  # principalSet de los bindings. Un valor con la URL completa o con barra
  # final produciría una condición que no matchea nunca, y el síntoma sería
  # "el pipeline no puede autenticarse" en vez de "el dato está mal escrito".
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository tiene que ser owner/repo, sin https:// ni barra final."
  }
}

variable "ingress" {
  description = "Exposición del servicio. El default no acepta tráfico directo de internet: entra por el load balancer, donde vive Cloud Armor."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
}

variable "labels" {
  description = "Labels operativos para tracking de costos y dueño."
  type        = map(string)
  default = {
    managed-by  = "terraform"
    cost-center = "appsec-demo"
    created-by  = "heimdall"
  }
}
