terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
  }

  # State remoto, versionado y cifrado. El bucket se crea fuera de este stack
  # (un backend no puede crear el bucket donde guarda su propio state).
  #
  # Queda comentado para que `terraform init -backend=false` y `validate`
  # corran sin ninguna credencial de GCP, que es como se valida este código
  # hoy en CI. Descomentar antes del primer apply real.
  #
  # backend "gcs" {
  #   bucket = "heimdall-tfstate"
  #   prefix = "cloud-run-gate"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
