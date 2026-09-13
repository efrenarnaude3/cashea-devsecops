# Equivalente de demo.ps1 para Linux, macOS y Git Bash. Mismos pasos, mismos
# nombres, para que el runbook sirva en cualquiera de los dos.

SHELL := /bin/bash
# python3 y no python: en macOS y en la mayoría de las distros `python` no
# existe.
PY ?= python3
OWNER ?= $(shell echo "$${HEIMDALL_OWNER}")
REPO_NAME ?= heimdall
NAMESPACE ?= notes-api
CLUSTER ?= heimdall
KYVERNO_VERSION ?= v1.13.4
IMAGE ?= ghcr.io/$(OWNER)/heimdall-notes-api:latest
RENDERED := .rendered

.DEFAULT_GOAL := help
.PHONY: help require-owner check gate up policy deploy deny status down install lint test build run tf-validate clean

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# --- Lo que corre sin Docker, sin nube y sin red ---------------------------

require-owner:
	@test -n "$(OWNER)" || (echo "Falta OWNER. Usá: make $(MAKECMDGOALS) OWNER=tu-usuario  (o exportá HEIMDALL_OWNER)" && exit 1)

check: ## Chequeo offline del repo + self-test del gate
	# --user evita el error de PEP 668 en Debian/Ubuntu recientes.
	$(PY) -m pip install --quiet --user pyyaml
	$(PY) scripts/verify_repo.py
	$(PY) scripts/gate.py --self-test

gate: ## El gate decide sobre los hallazgos de ejemplo
	@$(PY) scripts/gate.py \
		--findings demo/findings \
		--gate appsec/gate.yaml \
		--exceptions appsec/exceptions.yaml \
		--out gate-report; \
	code=$$?; \
	case $$code in \
		0) echo "==> El gate dejó pasar la corrida (exit 0)";; \
		1) echo "==> El gate BLOQUEÓ la corrida (exit 1), que es lo esperado en el demo";; \
		2) echo "==> Error de configuración: el gate no pudo decidir (exit 2)";; \
	esac

# --- El servicio -----------------------------------------------------------

install: ## Instala dependencias del servicio
	cd service && npm ci

lint: ## Lint + tipos
	cd service && npm run lint && npm run typecheck

test: ## Tests de las propiedades de seguridad
	cd service && npm test

build: require-owner ## Construye la imagen local
	docker build -t $(IMAGE) service

run: ## Corre la imagen local con el hardening de runtime
	docker run --rm -p 8080:8080 \
		--read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
		--cap-drop=ALL --security-opt=no-new-privileges:true \
		--memory=256m --cpus=0.5 --pids-limit=100 \
		-e DEMO_API_TOKEN=$${DEMO_API_TOKEN:?exportá DEMO_API_TOKEN primero} \
		$(IMAGE)

# --- El demo del control de admisión ---------------------------------------

up: ## Crea el clúster kind e instala Kyverno
	kind create cluster --name $(CLUSTER) --config deploy/kind/cluster.yaml || true
	kubectl apply -f https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/install.yaml
	# Los Deployments primero: `kubectl wait` sobre pods que todavía no fueron
	# creados devuelve "no matching resources found" al instante.
	kubectl -n kyverno rollout status deployment --timeout=300s
	kubectl wait --for=condition=Ready pod -l app.kubernetes.io/part-of=kyverno -n kyverno --timeout=300s
	kubectl apply -f deploy/k8s/namespace.yaml

policy: require-owner ## Aplica la política de admisión
	@mkdir -p $(RENDERED)
	@sed -e 's|__GITHUB_OWNER__|$(OWNER)|g' -e 's|__GITHUB_REPO__|$(REPO_NAME)|g' \
		policy/verify-image-signature.yaml > $(RENDERED)/policy.yaml
	kubectl apply -f $(RENDERED)/policy.yaml

deploy: require-owner ## Despliega la imagen firmada
	@mkdir -p $(RENDERED)
	@sed -e 's|__IMAGE__|$(IMAGE)|g' deploy/k8s/deployment.yaml > $(RENDERED)/deployment.yaml
	kubectl apply -f $(RENDERED)/deployment.yaml
	kubectl apply -f deploy/k8s/service.yaml
	kubectl rollout status deployment/notes-api -n $(NAMESPACE) --timeout=180s

deny: ## Intenta desplegar una imagen no autorizada (tiene que fallar)
	@echo "==> Esperando un rechazo del control de admisión:"
	@! kubectl apply -f deploy/k8s/unsigned-pod.yaml || (echo "XX El Pod fue admitido: la política no está activa" && exit 1)
	@echo "==> RECHAZADO. Es lo que Binary Authorization hace en Cloud Run."

status: ## Qué está corriendo y qué políticas hay
	kubectl get clusterpolicies.kyverno.io
	kubectl get pods -n $(NAMESPACE)

down: ## Borra el clúster
	kind delete cluster --name $(CLUSTER)

# --- El camino GCP (se valida, no se aplica) -------------------------------

tf-validate: ## fmt + validate del Terraform, sin credenciales
	terraform -chdir=terraform fmt -check -recursive -diff
	terraform -chdir=terraform init -backend=false
	terraform -chdir=terraform validate

clean: ## Borra artefactos locales
	rm -rf $(RENDERED) gate-report.md gate-report.json service/dist service/coverage
