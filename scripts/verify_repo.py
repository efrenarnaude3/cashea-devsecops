#!/usr/bin/env python3
"""
Chequeo de coherencia del repositorio, sin red y sin nube.

Corre todas las verificaciones que NO necesitan credenciales, ni Docker, ni las
herramientas de seguridad instaladas. Sirve en una máquina limpia, en un runner
sin red y como paso de CI. Es la respuesta corta a "¿cómo sabés que esto no
está roto antes de pushearlo?".

Qué verifica:

  1. Todos los .py compilan.
  2. Todos los YAML parsean, incluidos los de .github (que los glob normales
     se saltan por empezar con punto).
  3. Los workflows están bien cableados: cada `needs` nombra un job real y cada
     `needs.<job>.outputs.<x>` está declarado por ese job. Es una clase de bug
     invisible hasta que el workflow corre e imprime un string vacío.
  4. La configuración del gate es válida según el propio motor: importa
     scripts/gate.py y le pasa appsec/gate.yaml y appsec/exceptions.yaml. Si
     una excepción está mal formada, se entera acá y no en el PR de otro.
  5. El Deployment cumple el perfil `restricted` que el namespace exige, y la
     política de Kyverno apunta al mismo namespace que el Deployment usa.
  6. Terraform: llaves balanceadas, módulos que existen, ninguna service
     account key, ningún `containerscanning` (cobra por imagen) y alineación
     de `terraform fmt`.
  7. Coherencia de versiones de Node entre package.json, el Dockerfile, la
     imagen distroless y el workflow, y dependencias pinneadas de forma exacta.
     El lockfile se reporta aparte, como aviso.
  8. Que no haya ningún string con forma de credencial en el repo.

Salida: 0 si todo pasa (los avisos no cuentan), 1 si algo falla.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

REPO = Path(__file__).resolve().parents[1]
PASS = "PASS"
FAIL = "FAIL"
# WARN señala algo que hay que hacer pero que no es una incoherencia del repo:
# no rompe el build. El caso típico es el lockfile de npm, que se genera con
# una instalación y no se puede versionar antes de eso.
WARN = "WARN"

results: list[tuple[str, str, str]] = []


def record(status: str, check: str, detail: str = "") -> None:
    results.append((status, check, detail))


def iter_files(*patterns: str) -> list[Path]:
    found: list[Path] = []
    for pattern in patterns:
        found += [
            p
            for p in REPO.rglob(pattern)
            if not any(part in {"__pycache__", ".git", "node_modules", "dist", "coverage"} for part in p.parts)
        ]
    return sorted(set(found))


# --- 1. Python --------------------------------------------------------------


def check_python_syntax() -> None:
    files = iter_files("*.py")
    broken = []
    for path in files:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            broken.append(f"{path.relative_to(REPO)}: {exc}")
    if broken:
        record(FAIL, "Sintaxis Python", "; ".join(broken))
    else:
        record(PASS, "Sintaxis Python", f"{len(files)} archivo(s) compilan")


# --- 2. YAML ----------------------------------------------------------------


def load_yaml_files() -> dict[Path, list[object]]:
    documents: dict[Path, list[object]] = {}
    broken: list[str] = []
    files = iter_files("*.yml", "*.yaml")
    for path in files:
        try:
            documents[path] = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d is not None]
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:  # type: ignore[union-attr]
            broken.append(f"{path.relative_to(REPO)}: {exc}")
    if broken:
        record(FAIL, "Sintaxis YAML", "; ".join(broken))
    else:
        record(PASS, "Sintaxis YAML", f"{len(files)} archivo(s) parsean")
    return documents


# --- 3. Workflows -----------------------------------------------------------


def check_workflows(documents: dict[Path, list[object]]) -> None:
    workflow_dir = REPO / ".github" / "workflows"
    problems: list[str] = []
    checked = 0

    # Cobertura primero: `documents` solo tiene los archivos que parsearon, así
    # que sin esto un workflow roto se saltaría en silencio y este chequeo
    # reportaría PASS justo sobre el archivo que está mal.
    on_disk = set(workflow_dir.glob("*.yml")) | set(workflow_dir.glob("*.yaml"))
    for missing in sorted(on_disk - set(documents)):
        problems.append(f"{missing.name}: no parseó, así que no se revisó")

    for path, docs in documents.items():
        if workflow_dir not in path.parents:
            continue
        checked += 1
        workflow = docs[0] if docs else {}
        if not isinstance(workflow, dict):
            problems.append(f"{path.name}: no es un mapa")
            continue

        jobs = workflow.get("jobs") or {}
        if not jobs:
            problems.append(f"{path.name}: sin jobs")
            continue

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                problems.append(f"{path.name}:{job_name}: no es un mapa")
                continue
            if "runs-on" not in job and "uses" not in job:
                problems.append(f"{path.name}:{job_name}: sin runs-on")

            needs = job.get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            for dependency in needs:
                if dependency not in jobs:
                    problems.append(f"{path.name}:{job_name}: needs apunta a un job inexistente '{dependency}'")

            body = yaml.safe_dump(job, width=10_000)  # type: ignore[union-attr]
            for referenced, output_key in re.findall(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", body):
                if referenced not in needs:
                    problems.append(
                        f"{path.name}:{job_name}: usa needs.{referenced}.outputs pero '{referenced}' no está en needs"
                    )
                    continue
                declared = (jobs.get(referenced) or {}).get("outputs") or {}
                if output_key not in declared:
                    problems.append(f"{path.name}:{job_name}: needs.{referenced}.outputs.{output_key} no está declarado")

    if problems:
        record(FAIL, "Cableado de workflows", "; ".join(sorted(set(problems))))
    else:
        record(PASS, "Cableado de workflows", f"{checked} workflow(s) coherentes")


# --- 4. Configuración del gate ---------------------------------------------


def check_gate_config() -> None:
    """Valida gate.yaml y exceptions.yaml con el motor real, no con una copia
    de las reglas. Si el motor cambia, este chequeo cambia con él."""
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        import gate  # type: ignore[import-not-found]
    except ImportError as exc:
        record(FAIL, "Configuración del gate", f"no pude importar scripts/gate.py: {exc}")
        return

    from datetime import date

    problems: list[str] = []
    gate_path = REPO / "appsec" / "gate.yaml"
    exceptions_path = REPO / "appsec" / "exceptions.yaml"

    for path in (gate_path, exceptions_path):
        if not path.is_file():
            problems.append(f"falta {path.relative_to(REPO)}")
    if problems:
        record(FAIL, "Configuración del gate", "; ".join(problems))
        return

    raw_gate = yaml.safe_load(gate_path.read_text(encoding="utf-8")) or {}  # type: ignore[union-attr]
    raw_exceptions = yaml.safe_load(exceptions_path.read_text(encoding="utf-8")) or {}  # type: ignore[union-attr]

    config, config_errors = gate.parse_gate_config(raw_gate)
    _, waiver_errors = gate.parse_waivers(raw_exceptions, date.today())
    problems += config_errors + waiver_errors

    if config.mode == "enforce" and not config.vertical:
        problems.append("gate.yaml está en enforce pero no declara vertical: el gate se degradaría a preview")

    if problems:
        record(FAIL, "Configuración del gate", "; ".join(problems))
    else:
        record(PASS, "Configuración del gate", f"modo {config.mode}, adopción {config.adopted_at}, excepciones válidas")


# --- 5. Kubernetes y política ----------------------------------------------


def check_k8s_and_policy(documents: dict[Path, list[object]]) -> None:
    problems: list[str] = []

    deployment_path = REPO / "deploy" / "k8s" / "deployment.yaml"
    deployment = None
    for doc in documents.get(deployment_path, []):
        if isinstance(doc, dict) and doc.get("kind") == "Deployment":
            deployment = doc
            break

    namespace_of_deployment = ""
    if deployment is None:
        problems.append("deploy/k8s/deployment.yaml: no encontré el Deployment")
    else:
        try:
            namespace_of_deployment = deployment["metadata"].get("namespace", "")
            spec = deployment["spec"]["template"]["spec"]
            pod_sc = spec.get("securityContext") or {}
            container = spec["containers"][0]
            container_sc = container.get("securityContext") or {}
        except (KeyError, IndexError, TypeError) as exc:
            problems.append(f"deploy/k8s/deployment.yaml: manifiesto mal formado ({exc})")
            spec, pod_sc, container, container_sc = {}, {}, {}, {}

        if container and container.get("image") != "__IMAGE__":
            problems.append("deployment: la imagen debería ser __IMAGE__ (el script del demo la reemplaza)")
        if pod_sc.get("runAsNonRoot") is not True:
            problems.append("deployment: runAsNonRoot tiene que ser true (PSS restricted)")
        if (pod_sc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
            problems.append("deployment: seccompProfile.type tiene que ser RuntimeDefault (PSS restricted)")
        if container_sc.get("allowPrivilegeEscalation") is not False:
            problems.append("deployment: allowPrivilegeEscalation tiene que ser false")
        if container_sc.get("readOnlyRootFilesystem") is not True:
            problems.append("deployment: readOnlyRootFilesystem tiene que ser true")
        if (container_sc.get("capabilities") or {}).get("drop") != ["ALL"]:
            problems.append("deployment: capabilities.drop tiene que ser ['ALL']")
        if "resources" not in container or "limits" not in (container.get("resources") or {}):
            problems.append("deployment: el contenedor no tiene resource limits")

    policy_path = REPO / "policy" / "verify-image-signature.yaml"
    policy_docs = documents.get(policy_path, [])
    policy = policy_docs[0] if policy_docs else None
    if not isinstance(policy, dict):
        problems.append("policy/verify-image-signature.yaml: no encontré la ClusterPolicy")
    else:
        policy_spec = policy.get("spec") or {}
        if policy_spec.get("failurePolicy") != "Fail":
            problems.append("kyverno: failurePolicy tiene que ser Fail (un control que falla abierto no es un control)")

        rules = policy_spec.get("rules") or []
        if not any("verifyImages" in (rule or {}) for rule in rules):
            problems.append("kyverno: falta la regla verifyImages")
        if not any("validate" in (rule or {}) for rule in rules):
            problems.append("kyverno: falta la regla de registries permitidos")

        raw_policy = policy_path.read_text(encoding="utf-8")
        for placeholder in ("__GITHUB_OWNER__", "__GITHUB_REPO__"):
            if placeholder not in raw_policy:
                problems.append(f"kyverno: falta el marcador {placeholder} que reemplaza el script del demo")

        # El namespace de la política y el del Deployment tienen que coincidir,
        # o la política no se aplica a nada y el demo "pasa" por la razón
        # equivocada.
        if namespace_of_deployment and namespace_of_deployment not in raw_policy:
            problems.append(
                f"kyverno: la política no menciona el namespace '{namespace_of_deployment}' que usa el Deployment"
            )

    if problems:
        record(FAIL, "Kubernetes y política", "; ".join(problems))
    else:
        record(PASS, "Kubernetes y política", "PSS restricted + Kyverno apuntando al namespace correcto")


# --- 6. Terraform -----------------------------------------------------------

ASSIGNMENT = re.compile(r'^([A-Za-z_][\w-]*|"[^"]+")\s*=\s*\S')
META_ARGUMENTS = {"source", "for_each", "count", "depends_on", "providers", "version"}


def check_terraform() -> None:
    problems: list[str] = []
    terraform_dir = REPO / "terraform"
    files = sorted(terraform_dir.rglob("*.tf"))

    for path in files:
        text = path.read_text(encoding="utf-8")
        stripped = re.sub(r"#.*", "", text)
        if stripped.count("{") != stripped.count("}"):
            problems.append(f"{path.relative_to(REPO)}: llaves desbalanceadas")
        if "google_service_account_key" in stripped:
            problems.append(f"{path.relative_to(REPO)}: crea una service account key (nunca en este repo)")
        if "containerscanning.googleapis.com" in stripped:
            problems.append(
                f"{path.relative_to(REPO)}: habilita containerscanning, que cobra USD 0.26 por imagen. "
                "El escaneo lo hace Trivy en CI."
            )
        for module_source in re.findall(r'source\s*=\s*"(\./[^"]+)"', stripped):
            if not (path.parent / module_source).resolve().is_dir():
                problems.append(f"{path.relative_to(REPO)}: el módulo '{module_source}' no existe")

    problems += _check_module_inputs(terraform_dir)
    problems += _check_alignment(files)

    if problems:
        record(FAIL, "Terraform", "; ".join(problems))
    else:
        record(PASS, "Terraform", f"{len(files)} archivo(s), módulos e inputs coherentes, formato OK")


def _check_module_inputs(terraform_dir: Path) -> list[str]:
    module_root = terraform_dir / "modules"
    if not module_root.is_dir():
        return ["terraform/modules/ no existe"]

    declared: dict[str, set[str]] = {}
    for module_dir in module_root.iterdir():
        if not module_dir.is_dir():
            continue
        names: set[str] = set()
        for tf_file in module_dir.glob("*.tf"):
            names |= set(re.findall(r'variable\s+"([^"]+)"', tf_file.read_text(encoding="utf-8")))
        declared[module_dir.name] = names

    problems: list[str] = []
    root_main = (terraform_dir / "main.tf").read_text(encoding="utf-8")
    for block in re.finditer(r'module\s+"([^"]+)"\s*\{(.*?)\n\}', root_main, re.S):
        body = block.group(2)
        source = re.search(r'source\s*=\s*"\./modules/([^"]+)"', body)
        if not source:
            continue
        passed = set(re.findall(r"^\s{2}([a-z_]+)\s*=", body, re.M)) - META_ARGUMENTS
        for name in sorted(passed - declared.get(source.group(1), set())):
            problems.append(f"módulo '{block.group(1)}': pasa '{name}', que modules/{source.group(1)} no declara")
    return problems


def _check_alignment(files: list[Path]) -> list[str]:
    """Aproxima `terraform fmt -check`, que es lo que gatea el workflow de IaC.
    Solo mira corridas de dos o más asignaciones simples con la misma sangría."""
    problems: list[str] = []
    for path in files:
        group: list[tuple[int, str, str]] = []
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            stripped = line.strip()
            match = ASSIGNMENT.match(stripped)
            balanced = stripped.count("{") == stripped.count("}") and stripped.count("[") == stripped.count("]")
            if match and balanced:
                group.append((number, line, match.group(1)))
                continue
            problems += _alignment_problems(path, group)
            group = []
        problems += _alignment_problems(path, group)
    return problems


def _alignment_problems(path: Path, group: list[tuple[int, str, str]]) -> list[str]:
    if len(group) < 2:
        return []
    indents = {len(line) - len(line.lstrip()) for _, line, _ in group}
    if len(indents) != 1:
        return []
    expected = max(len(name) for _, _, name in group) + 1
    problems = []
    for number, line, _ in group:
        indent = len(line) - len(line.lstrip())
        column = line.index("=", indent) - indent
        if column != expected:
            problems.append(f"{path.relative_to(REPO)}:{number}: '=' en la columna {column}, se esperaba {expected}")
    return problems


# --- 7. Coherencia de versiones y pines ------------------------------------


def check_node_coherence() -> None:
    problems: list[str] = []
    service = REPO / "service"

    package = json.loads((service / "package.json").read_text(encoding="utf-8"))
    dockerfile = (service / "Dockerfile").read_text(encoding="utf-8")
    workflow = (REPO / ".github" / "workflows" / "ci-security.yml").read_text(encoding="utf-8")

    build_match = re.search(r"FROM node:(\d+)", dockerfile)
    runtime_match = re.search(r"distroless/nodejs(\d+)", dockerfile)
    ci_match = re.search(r'NODE_VERSION:\s*"(\d+)"', workflow)

    build_major = build_match.group(1) if build_match else None
    runtime_major = runtime_match.group(1) if runtime_match else None
    ci_major = ci_match.group(1) if ci_match else None

    versions = {"build stage": build_major, "imagen distroless": runtime_major, "workflow": ci_major}
    distinct = {v for v in versions.values() if v}
    if len(distinct) > 1:
        problems.append(f"versiones de Node distintas entre sí: {versions}")
    if not distinct:
        problems.append("no pude determinar la versión de Node en ningún lado")

    engines = str((package.get("engines") or {}).get("node", ""))
    if build_major and build_major not in engines:
        problems.append(f"package.json engines.node ({engines}) no incluye Node {build_major}")

    for section in ("dependencies", "devDependencies"):
        for name, version in (package.get(section) or {}).items():
            if re.match(r"^[\^~]", str(version)):
                problems.append(f"package.json: {name} usa rango ({version}); este repo pinea exacto")

    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    for must_ignore in (".env", "*.tfstate", "*.tfvars"):
        if must_ignore not in gitignore:
            problems.append(f".gitignore no ignora {must_ignore}")

    if problems:
        record(FAIL, "Versiones y pines", "; ".join(problems))
    else:
        record(PASS, "Versiones y pines", f"Node {build_major} en todos lados, dependencias exactas")

    # Aparte, y sin romper el build: el lockfile no se puede versionar hasta
    # que alguien corra la instalación una vez.
    if not (service / "package-lock.json").is_file():
        record(
            WARN,
            "Lockfile de npm",
            "falta service/package-lock.json. `npm ci` lo exige y sin él el build no es reproducible: "
            "corré `npm install --package-lock-only` dentro de service/ y commitealo",
        )
    else:
        record(PASS, "Lockfile de npm", "presente")


# --- 8. Secretos ------------------------------------------------------------

SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "clave privada": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Google API key": r"AIza[0-9A-Za-z_-]{35}",
    "Slack token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "GitHub token": r"gh[pousr]_[0-9A-Za-z]{36}",
}


def check_no_secrets() -> None:
    problems: list[str] = []
    for path in iter_files("*"):
        if path.is_dir() or path.suffix in {".zip", ".png", ".jpg", ".pyc", ".ico"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, text):
                problems.append(f"{path.relative_to(REPO)}: posible {label}")
    if problems:
        record(FAIL, "Sin secretos hardcodeados", "; ".join(problems))
    else:
        record(PASS, "Sin secretos hardcodeados", "ningún string con forma de credencial")


def main() -> int:
    if yaml is None:
        print("Falta PyYAML: pip install pyyaml")
        return 1

    check_python_syntax()
    documents = load_yaml_files()
    check_workflows(documents)
    check_gate_config()
    check_k8s_and_policy(documents)
    check_terraform()
    check_node_coherence()
    check_no_secrets()

    width = max(len(check) for _, check, _ in results)
    print()
    for status, check, detail in results:
        print(f"[{status}] {check.ljust(width)}  {detail}")

    failures = [r for r in results if r[0] == FAIL]
    warnings = [r for r in results if r[0] == WARN]
    print()
    summary = f"{len(results) - len(failures) - len(warnings)}/{len(results)} chequeos pasaron"
    if warnings:
        summary += f", {len(warnings)} con aviso"
    if failures:
        summary += f", {len(failures)} fallando"
    print(summary)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
