# Qué bloquea, qué no, y por qué

Un pipeline con demasiados gates duros entrena al equipo a pedir excepciones
por costumbre. Uno sin gates no sirve. Esta es la decisión, control por control.

| Control | Dónde | Bloquea | Por qué |
|---|---|---|---|
| Chequeo de coherencia del repo | job `quality` | Sí | Detecta incoherencias que si no aparecen recién en runtime: un `needs` incompleto, un manifiesto que no cumple el perfil del namespace, versiones de Node desalineadas |
| Self-test del gate | job `quality` | Sí | Si la lógica de decisión se rompe, mejor enterarse acá que el día que tenga que bloquear algo |
| Lint, tipos y tests | job `quality` | Sí | Los tests afirman propiedades de seguridad: authn requerida, campos no declarados rechazados, headers, IDs UUID, rate limit |
| SCA de producción (`npm audit --omit=dev`) | job `sca` | No por sí mismo | Alimenta al gate: son las dependencias que viajan en la imagen |
| SCA del toolchain (`npm audit` completo) | job `sca` | No | Compiladores, linters y test runners no están en la imagen. Van al backlog con SLA y a los PRs de Dependabot, no a frenar un deploy |
| Trivy filesystem | job `sca` | No por sí mismo | Produce el JSON; quien decide es el gate |
| Secretos en el diff | job `secrets` | Sí | Un secreto commiteado es explotable en minutos. Cero tolerancia |
| Escaneo de imagen | job `build-scan-gate-sign` | No por sí mismo | Alimenta al gate |
| **El gate** | job `build-scan-gate-sign` | Sí, en `enforce` | Es el único lugar donde se decide. Y decide antes del push al registry |
| Firma y attestation | job `build-scan-gate-sign` | No aplica | Solo corre sobre lo que el gate ya aprobó |
| Admisión (Kyverno / Binary Authorization) | el clúster | Sí | Defensa en profundidad: un `kubectl apply` manual también es rechazado |
| Pod Security Admission | label del namespace | Sí | El API server rechaza pods que no cumplen `restricted`, aunque el manifiesto se haya olvidado del securityContext |
| CodeQL | workflow propio | Sí, vía branch protection | En su propio workflow para que el escáner lento no frene el feedback del PR |
| Checkov y tfsec | job `iac-scan` | Sí | Un módulo malo se replica a escala |

## Qué no bloquea, a propósito

- Hallazgos Medium y Low: se reportan y entran al backlog con su SLA.
- Hallazgos sin fix disponible: no son accionables dentro del PR que los
  encuentra.
- Hallazgos anteriores a la fecha de adopción del repo.
- Un repo en modo `preview`: mide y reporta, nunca bloquea. Es el estado
  inicial obligatorio.

## Qué sí rompe la corrida aunque el repo esté en preview

Una excepción sin alguno de sus cuatro campos, con una fecha inválida, o con
más de 90 días de vigencia. Eso no es un hallazgo: es el control roto, y sale
con exit 2 en vez de exit 0.

## Manejo de secretos en el pipeline

- Ninguna credencial de larga vida: la firma es keyless y la autenticación a
  GCP es por OIDC.
- Ninguna service account key en el repo ni en GCP. `verify_repo.py` falla si
  aparece un `google_service_account_key` en el Terraform.
- El token de la app se crea desde Secret Manager, fuera del repo. No hay
  ningún manifiesto de Secret versionado, ni con valores de ejemplo: un
  `kubectl apply` de un placeholder pisaría el secreto real del clúster.
- El state de Terraform va a GCS con versioning. Nunca local, nunca commiteado.
