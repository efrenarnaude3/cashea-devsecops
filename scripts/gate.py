#!/usr/bin/env python3
"""
Heimdall — el motor de decisión del gate.

Lee los hallazgos que las herramientas ya produjeron (Trivy, npm audit, SARIF
de Semgrep o CodeQL), los cruza contra el contrato del repo (appsec/gate.yaml)
y contra las excepciones vigentes (appsec/exceptions.yaml), y decide una sola
cosa: si esta corrida pasa o se bloquea.

No escanea nada. No crea hallazgos ni tickets. Esa es la decisión de diseño
central: sumar un scanner más habría creado otra fuente de hallazgos y otro
lugar donde mirarlos. El gate decide con la información que ya existe.

Un hallazgo bloquea cuando cumple TODAS estas condiciones:

  1. Su severidad está en `block_severities` (por defecto CRITICAL y HIGH).
  2. Tiene fix disponible, o `ignore_unfixed` está en false.
  3. Es posterior a `adopted_at` (delta gating: el backlog histórico lo drena
     el proceso de gestión de vulnerabilidades, no el gate).
  4. No está cubierto por una excepción vigente.

Códigos de salida:
  0  la corrida pasa (o está en preview, que nunca bloquea)
  1  la corrida se bloquea (solo en enforce)
  2  error de configuración: el gate no pudo decidir

El código 2 existe a propósito y también dispara en preview. Una excepción sin
aprobador o sin fecha de vencimiento no es un hallazgo más: es el control roto,
y un control roto no puede reportar "todo bien".

Uso:
    python scripts/gate.py --findings reports/ --gate appsec/gate.yaml \\
        --exceptions appsec/exceptions.yaml --out gate-report

    python scripts/gate.py --self-test     # no necesita PyYAML ni archivos
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
    import yaml

    HAVE_YAML = True
except ImportError:  # pragma: no cover - depende del entorno, no de la lógica
    HAVE_YAML = False

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SLA_DAYS = {"CRITICAL": 3, "HIGH": 7, "MEDIUM": 30, "LOW": 90, "UNKNOWN": 90}
MAX_WAIVER_DAYS = 90
# Siempre obligatorios. Además hace falta `id` o `package`: una excepción que
# no dice a qué aplica no es una excepción.
REQUIRED_WAIVER_FIELDS = ("reason", "approved_by", "expires_on")

EXIT_PASS = 0
EXIT_BLOCKED = 1
EXIT_CONFIG_ERROR = 2

# npm audit usa "moderate"; el resto del mundo usa "medium".
SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW", "INFO": "LOW"}
SARIF_LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------


@dataclass
class GateConfig:
    mode: str = "preview"
    adopted_at: date | None = None
    block_severities: tuple[str, ...] = ("CRITICAL", "HIGH")
    ignore_unfixed: bool = True
    vertical: str = ""

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"


# Cada herramienta identifica el mismo hallazgo distinto. npm audit no expone
# el CVE: en su JSON viene la URL del advisory
# ("https://github.com/advisories/GHSA-4pg4-qvpc-4q3h"), mientras que Trivy usa
# el ID pelado. Sin normalizar, una excepción escrita como "GHSA-4pg4-qvpc-4q3h"
# no matchearía el hallazgo de npm y el equipo pensaría que el gate ignora sus
# excepciones.
IDENTIFIER = re.compile(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,})", re.IGNORECASE)


def identity_keys(value: str) -> set[str]:
    """Claves por las que un hallazgo y una excepción se consideran el mismo.

    Incluye el string completo (para reglas de SAST, que no tienen CVE) y
    cualquier GHSA o CVE que aparezca adentro.
    """
    text = (value or "").strip()
    keys = {text.upper()} if text else set()
    keys |= {match.group(0).upper() for match in IDENTIFIER.finditer(text)}
    return keys


@dataclass
class Waiver:
    reason: str
    approved_by: str
    expires_on: date
    id: str = ""
    package: str = ""

    def covers(self, finding: "Finding") -> bool:
        # Por paquete: para cuando una sola causa produce muchos advisories
        # (multer, por ejemplo, tiene ocho). Escribir ocho excepciones con la
        # misma justificación no agrega control, agrega fricción, y la
        # fricción es lo que hace que un equipo deje de usar el proceso.
        #
        # El precio es real y hay que decirlo: un advisory NUEVO del mismo
        # paquete queda cubierto sin que nadie lo mire. Por eso la excepción
        # por paquete vence igual que cualquier otra, y al vencer obliga a
        # volver a justificarla con la lista de advisories a la vista.
        if self.package and finding.component.strip().lower() == self.package.strip().lower():
            return True
        if self.id:
            return bool(identity_keys(self.id) & identity_keys(finding.id))
        return False

    def is_valid_on(self, today: date) -> bool:
        return self.expires_on >= today

    def describe(self) -> str:
        return f"paquete {self.package}" if self.package else self.id


@dataclass
class Finding:
    id: str
    severity: str
    component: str
    title: str
    tool: str
    detected_on: date | None = None
    fixed_version: str = ""

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_version)


@dataclass
class Decision:
    finding: Finding
    blocking: bool
    reason: str


@dataclass
class Report:
    config: GateConfig
    decisions: list[Decision] = field(default_factory=list)
    config_errors: list[str] = field(default_factory=list)
    parsed_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def blocking(self) -> list[Decision]:
        return [d for d in self.decisions if d.blocking]

    def exit_code(self) -> int:
        if self.config_errors:
            return EXIT_CONFIG_ERROR
        if self.blocking and self.config.enforcing:
            return EXIT_BLOCKED
        return EXIT_PASS


# --------------------------------------------------------------------------
# Normalización
# --------------------------------------------------------------------------


def normalize_severity(raw: str | None) -> str:
    value = (raw or "UNKNOWN").strip().upper()
    value = SEVERITY_ALIASES.get(value, value)
    return value if value in SEVERITY_ORDER else "UNKNOWN"


def parse_date(value: Any) -> date | None:
    """Acepta date, datetime y strings ISO (con o sin Z). None si no se puede."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d").date()
        except ValueError:
            return None


# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------


def parse_gate_config(raw: dict[str, Any]) -> tuple[GateConfig, list[str]]:
    errors: list[str] = []
    mode = str(raw.get("mode", "preview")).strip().lower()
    if mode not in {"preview", "enforce"}:
        errors.append(f"gate.yaml: mode '{mode}' no es válido (preview | enforce)")
        mode = "preview"

    adopted_at = parse_date(raw.get("adopted_at"))
    if raw.get("adopted_at") and adopted_at is None:
        errors.append(f"gate.yaml: adopted_at '{raw.get('adopted_at')}' no es una fecha ISO")

    severities = raw.get("block_severities") or ["CRITICAL", "HIGH"]
    normalized = tuple(normalize_severity(s) for s in severities)
    unknown = [s for s in normalized if s == "UNKNOWN"]
    if unknown:
        errors.append("gate.yaml: block_severities tiene una severidad desconocida")

    config = GateConfig(
        mode=mode,
        adopted_at=adopted_at,
        block_severities=normalized,
        ignore_unfixed=bool(raw.get("ignore_unfixed", True)),
        vertical=str(raw.get("vertical", "") or "").strip(),
    )
    return config, errors


def parse_waivers(raw: dict[str, Any], today: date) -> tuple[list[Waiver], list[str]]:
    """Valida las excepciones de forma estricta.

    Es acá donde el KPI de "0% de bypass sin justificación" deja de ser una
    intención y pasa a ser un mecanismo: sin los cuatro campos, la excepción no
    existe y la corrida falla con error de configuración.
    """
    errors: list[str] = []
    waivers: list[Waiver] = []

    entries = raw.get("exceptions")
    if entries is None:
        return waivers, errors
    if not isinstance(entries, list):
        return waivers, ["exceptions.yaml: 'exceptions' tiene que ser una lista"]

    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"exceptions.yaml: la entrada #{index} no es un mapa")
            continue

        label = str(entry.get("id") or entry.get("package") or "sin id ni package")

        missing = [f for f in REQUIRED_WAIVER_FIELDS if not str(entry.get(f, "") or "").strip()]
        if missing:
            errors.append(
                f"exceptions.yaml: la entrada #{index} ({label}) no tiene {', '.join(missing)}. "
                "reason, approved_by y expires_on son obligatorios siempre."
            )
            continue

        target_id = str(entry.get("id", "") or "").strip()
        target_package = str(entry.get("package", "") or "").strip()
        if not target_id and not target_package:
            errors.append(
                f"exceptions.yaml: la entrada #{index} no declara ni `id` ni `package`. "
                "Una excepción que no dice a qué aplica no es una excepción."
            )
            continue

        expires_on = parse_date(entry.get("expires_on"))
        if expires_on is None:
            errors.append(f"exceptions.yaml: {label} tiene un expires_on que no es fecha ISO")
            continue

        if (expires_on - today).days > MAX_WAIVER_DAYS:
            errors.append(
                f"exceptions.yaml: {label} vence en {(expires_on - today).days} días. "
                f"El máximo son {MAX_WAIVER_DAYS}: una excepción que no vence es una decisión silenciosa."
            )
            continue

        waivers.append(
            Waiver(
                id=target_id,
                package=target_package,
                reason=str(entry["reason"]).strip(),
                approved_by=str(entry["approved_by"]).strip(),
                expires_on=expires_on,
            )
        )

    return waivers, errors


# --------------------------------------------------------------------------
# Parsers de hallazgos
# --------------------------------------------------------------------------


def parse_trivy(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    id=vuln.get("VulnerabilityID", ""),
                    severity=normalize_severity(vuln.get("Severity")),
                    component=vuln.get("PkgName") or target,
                    title=(vuln.get("Title") or vuln.get("VulnerabilityID") or "").strip(),
                    tool="trivy",
                    detected_on=parse_date(vuln.get("PublishedDate")),
                    fixed_version=str(vuln.get("FixedVersion") or ""),
                )
            )
        for secret in result.get("Secrets") or []:
            # Un secreto nunca es legacy ni se ignora por falta de fix: la
            # remediación es rotarlo, y eso se puede hacer siempre.
            findings.append(
                Finding(
                    id=secret.get("RuleID", "secret"),
                    severity=normalize_severity(secret.get("Severity") or "CRITICAL"),
                    component=target,
                    title=(secret.get("Title") or "posible secreto en el repo").strip(),
                    tool="trivy-secret",
                    detected_on=None,
                    fixed_version="rotar",
                )
            )
    return findings


def parse_npm_audit(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for name, entry in (data.get("vulnerabilities") or {}).items():
        if not isinstance(entry, dict):
            continue
        advisories = [v for v in (entry.get("via") or []) if isinstance(v, dict)]
        fix_available = bool(entry.get("fixAvailable"))
        if not advisories:
            findings.append(
                Finding(
                    id=f"npm:{name}",
                    severity=normalize_severity(entry.get("severity")),
                    component=name,
                    title=f"dependencia vulnerable: {name}",
                    tool="npm-audit",
                    fixed_version="disponible" if fix_available else "",
                )
            )
            continue
        for advisory in advisories:
            findings.append(
                Finding(
                    id=str(advisory.get("cve") or advisory.get("url") or advisory.get("source") or name),
                    severity=normalize_severity(advisory.get("severity") or entry.get("severity")),
                    component=name,
                    title=str(advisory.get("title") or f"dependencia vulnerable: {name}"),
                    tool="npm-audit",
                    fixed_version="disponible" if fix_available else "",
                )
            )
    return findings


def parse_sarif(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = str(driver.get("name") or "sarif").lower()
        for result in run.get("results") or []:
            locations = result.get("locations") or []
            component = ""
            if locations:
                physical = locations[0].get("physicalLocation") or {}
                component = (physical.get("artifactLocation") or {}).get("uri", "")
            findings.append(
                Finding(
                    id=str(result.get("ruleId") or "sin-regla"),
                    severity=_sarif_severity(result),
                    component=component,
                    title=str((result.get("message") or {}).get("text") or "").strip(),
                    tool=tool_name,
                    # SARIF no trae fecha de publicación. Sin fecha, el hallazgo
                    # se trata como nuevo: no se puede probar que sea legacy, y
                    # ante la duda el gate no regala el beneficio.
                    detected_on=None,
                    fixed_version="disponible",
                )
            )
    return findings


def _sarif_severity(result: dict[str, Any]) -> str:
    props = result.get("properties") or {}
    raw_score = props.get("security-severity")
    if raw_score is not None:
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = -1.0
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        if score >= 0:
            return "LOW"
    return SARIF_LEVEL_TO_SEVERITY.get(str(result.get("level", "warning")), "MEDIUM")


def load_findings(paths: list[Path], report: Report) -> list[Finding]:
    """Detecta el formato por contenido, no por nombre de archivo.

    Así, sumar una herramienta al pipeline no obliga a tocar este script:
    alcanza con que suba su JSON o su SARIF como artifact.
    """
    findings: list[Finding] = []
    for path in sorted(paths):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report.skipped_files.append(f"{path.name} (no es JSON legible)")
            continue

        if not isinstance(data, dict):
            report.skipped_files.append(f"{path.name} (formato no reconocido)")
            continue

        if "runs" in data:
            findings.extend(parse_sarif(data))
        elif "Results" in data or "SchemaVersion" in data:
            findings.extend(parse_trivy(data))
        elif "vulnerabilities" in data:
            findings.extend(parse_npm_audit(data))
        else:
            report.skipped_files.append(f"{path.name} (formato no reconocido)")
            continue

        report.parsed_files.append(path.name)
    return findings


# --------------------------------------------------------------------------
# Decisión
# --------------------------------------------------------------------------


def evaluate(
    findings: list[Finding],
    config: GateConfig,
    waivers: list[Waiver],
    today: date,
) -> list[Decision]:
    decisions: list[Decision] = []

    for finding in findings:
        if finding.severity not in config.block_severities:
            decisions.append(Decision(finding, False, f"severidad {finding.severity}: se reporta, no bloquea"))
            continue

        if config.ignore_unfixed and not finding.has_fix:
            decisions.append(Decision(finding, False, "sin fix disponible: no es accionable en este PR"))
            continue

        if config.adopted_at and finding.detected_on and finding.detected_on < config.adopted_at:
            decisions.append(
                Decision(finding, False, f"anterior a la adopción ({finding.detected_on} < {config.adopted_at})")
            )
            continue

        waiver = next((w for w in waivers if w.covers(finding)), None)
        if waiver is not None:
            if waiver.is_valid_on(today):
                decisions.append(
                    Decision(
                        finding,
                        False,
                        f"excepción ({waiver.describe()}) vigente hasta {waiver.expires_on}, aprobó {waiver.approved_by}",
                    )
                )
            else:
                decisions.append(
                    Decision(finding, True, f"excepción ({waiver.describe()}) vencida el {waiver.expires_on}")
                )
            continue

        decisions.append(Decision(finding, True, f"{finding.severity} nuevo y sin excepción"))

    return decisions


def build_report(
    findings: list[Finding],
    config: GateConfig,
    waivers: list[Waiver],
    today: date,
    report: Report,
) -> Report:
    # Un repo sin vertical no puede pasar a enforce: el control no sabría a
    # quién le está bloqueando el merge ni a quién avisarle.
    if config.enforcing and not config.vertical:
        report.notes.append("Sin `vertical` declarada: el gate queda en preview aunque gate.yaml diga enforce.")
        config.mode = "preview"

    report.decisions = evaluate(findings, config, waivers, today)
    return report


# --------------------------------------------------------------------------
# Salida
# --------------------------------------------------------------------------


def render_markdown(report: Report) -> str:
    config = report.config
    blocking = report.blocking
    lines: list[str] = ["# Heimdall — resultado del gate", ""]

    if report.config_errors:
        lines.append("**ERROR DE CONFIGURACIÓN — el gate no pudo decidir**")
        lines.append("")
        lines += [f"- {error}" for error in report.config_errors]
        lines.append("")
        return "\n".join(lines)

    if config.enforcing:
        estado = "BLOQUEADO" if blocking else "PASA"
    else:
        estado = f"PREVIEW: no bloquea, habría bloqueado {len(blocking)}"

    lines.append(f"**Modo `{config.mode}` · {estado}**")
    lines.append("")
    lines.append(
        f"{len(report.decisions)} hallazgo(s) evaluado(s) sobre {len(report.parsed_files)} reporte(s). "
        f"Adopción: {config.adopted_at or 'sin fecha'} · Vertical: {config.vertical or 'sin declarar'}"
    )
    lines.append("")

    for note in report.notes:
        lines.append(f"> {note}")
    if report.notes:
        lines.append("")

    if blocking:
        lines += ["## Bloquean", "", "| Severidad | ID | Componente | Motivo | SLA |", "|---|---|---|---|---|"]
        for decision in sorted(blocking, key=lambda d: SEVERITY_ORDER.index(d.finding.severity)):
            f = decision.finding
            lines.append(
                f"| {f.severity} | {f.id} | {f.component} | {decision.reason} | {SLA_DAYS[f.severity]} día(s) |"
            )
        lines.append("")

    non_blocking = [d for d in report.decisions if not d.blocking]
    if non_blocking:
        lines += ["## No bloquean", "", "| Severidad | ID | Componente | Por qué pasa |", "|---|---|---|---|"]
        for decision in sorted(non_blocking, key=lambda d: SEVERITY_ORDER.index(d.finding.severity)):
            f = decision.finding
            lines.append(f"| {f.severity} | {f.id} | {f.component} | {decision.reason} |")
        lines.append("")

    if not report.decisions:
        lines += ["Ninguna herramienta reportó hallazgos en esta corrida.", ""]

    if report.skipped_files:
        lines += ["## Entradas ignoradas", ""] + [f"- {name}" for name in report.skipped_files] + [""]

    return "\n".join(lines)


def write_outputs(report: Report, basename: str) -> None:
    markdown_path = Path(f"{basename}.md")
    json_path = Path(f"{basename}.json")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")

    payload = {
        "mode": report.config.mode,
        "adopted_at": str(report.config.adopted_at) if report.config.adopted_at else None,
        "vertical": report.config.vertical,
        "exit_code": report.exit_code(),
        "config_errors": report.config_errors,
        "blocking_count": len(report.blocking),
        "total_findings": len(report.decisions),
        "parsed_files": report.parsed_files,
        "skipped_files": report.skipped_files,
        "findings": [
            {**asdict(d.finding), "blocking": d.blocking, "reason": d.reason, "detected_on": str(d.finding.detected_on)}
            for d in report.decisions
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _finding(**kwargs: Any) -> Finding:
    base: dict[str, Any] = {
        "id": "CVE-2026-0001",
        "severity": "CRITICAL",
        "component": "demo-pkg",
        "title": "hallazgo de prueba",
        "tool": "self-test",
        "detected_on": date(2026, 9, 20),
        "fixed_version": "1.2.3",
    }
    base.update(kwargs)
    return Finding(**base)


def _run_case(
    findings: list[Finding],
    gate_raw: dict[str, Any],
    waivers_raw: dict[str, Any],
    today: date,
) -> Report:
    config, config_errors = parse_gate_config(gate_raw)
    waivers, waiver_errors = parse_waivers(waivers_raw, today)
    report = Report(config=config, config_errors=config_errors + waiver_errors)
    report.parsed_files.append("self-test")
    return build_report(findings, config, waivers, today, report)


def self_test() -> int:
    """Casos que cubren cada rama de la decisión. Solo stdlib: corre sin PyYAML
    y sin archivos, así que verifica la lógica incluso en una máquina limpia."""
    today = date(2026, 9, 12)
    enforce = {"mode": "enforce", "adopted_at": date(2026, 9, 12), "vertical": "appsec"}
    preview = {**enforce, "mode": "preview"}
    sin_excepciones: dict[str, Any] = {"exceptions": []}

    cases: list[tuple[str, Report, int, int]] = []

    # 1. Critical nuevo, sin excepción, en enforce: bloquea.
    cases.append(("critical nuevo bloquea en enforce", _run_case([_finding()], enforce, sin_excepciones, today), 1, 1))

    # 2. El mismo caso en preview: no bloquea, pero lo cuenta.
    cases.append(("preview nunca bloquea", _run_case([_finding()], preview, sin_excepciones, today), 0, 1))

    # 3. Hallazgo anterior a la adopción: pasa (delta gating).
    legacy = _finding(detected_on=date(2026, 1, 5))
    cases.append(("legacy no bloquea", _run_case([legacy], enforce, sin_excepciones, today), 0, 0))

    # 4. Excepción vigente: pasa.
    vigente = {
        "exceptions": [
            {
                "id": "CVE-2026-0001",
                "reason": "No alcanzable desde ningún endpoint",
                "approved_by": "appsec",
                "expires_on": date(2026, 10, 1),
            }
        ]
    }
    cases.append(("excepción vigente desbloquea", _run_case([_finding()], enforce, vigente, today), 0, 0))

    # 5. Excepción vencida: vuelve a bloquear sola.
    vencida = {"exceptions": [{**vigente["exceptions"][0], "expires_on": date(2026, 9, 11)}]}
    cases.append(("excepción vencida vuelve a bloquear", _run_case([_finding()], enforce, vencida, today), 1, 1))

    # 6. Excepción sin aprobador: error de configuración, no "todo bien".
    sin_aprobador = {"exceptions": [{**vigente["exceptions"][0], "approved_by": ""}]}
    cases.append(("excepción sin aprobador es error", _run_case([_finding()], enforce, sin_aprobador, today), 2, 1))

    # 7. Excepción a más de 90 días: error de configuración.
    eterna = {"exceptions": [{**vigente["exceptions"][0], "expires_on": date(2027, 9, 1)}]}
    cases.append(("excepción a más de 90 días es error", _run_case([_finding()], enforce, eterna, today), 2, 1))

    # 8. Sin fix disponible con ignore_unfixed: pasa.
    sin_fix = _finding(fixed_version="")
    cases.append(("sin fix no bloquea", _run_case([sin_fix], enforce, sin_excepciones, today), 0, 0))

    # 9. Severidad por debajo del umbral: pasa.
    medium = _finding(severity="MEDIUM")
    cases.append(("medium no bloquea", _run_case([medium], enforce, sin_excepciones, today), 0, 0))

    # 10. Enforce sin vertical: degrada a preview en vez de bloquear a ciegas.
    sin_vertical = {"mode": "enforce", "adopted_at": date(2026, 9, 12), "vertical": ""}
    report_sin_vertical = _run_case([_finding()], sin_vertical, sin_excepciones, today)
    cases.append(("sin vertical degrada a preview", report_sin_vertical, 0, 1))

    # 11. Un SARIF sin fecha se trata como nuevo.
    sarif_like = _finding(detected_on=None, id="js/sql-injection", tool="codeql")
    cases.append(("hallazgo sin fecha bloquea", _run_case([sarif_like], enforce, sin_excepciones, today), 1, 1))

    # 12. Una excepción escrita con el GHSA pelado cubre el hallazgo que npm
    # audit reporta como URL del advisory, y al revés.
    npm_like = _finding(id="https://github.com/advisories/GHSA-4pg4-qvpc-4q3h", tool="npm-audit")
    por_ghsa = {
        "exceptions": [
            {
                "id": "GHSA-4pg4-qvpc-4q3h",
                "reason": "El paquete no es alcanzable desde ningún endpoint",
                "approved_by": "appsec",
                "expires_on": date(2026, 10, 1),
            }
        ]
    }
    cases.append(("excepción por GHSA cubre la URL de npm", _run_case([npm_like], enforce, por_ghsa, today), 0, 0))

    # 13. Una excepción por paquete cubre todos sus advisories a la vez.
    por_paquete = {
        "exceptions": [
            {
                "package": "multer",
                "reason": "El servicio no expone ningún endpoint de upload",
                "approved_by": "appsec",
                "expires_on": date(2026, 10, 1),
            }
        ]
    }
    multer_uno = _finding(id="https://github.com/advisories/GHSA-xf7r-hgr6-v32p", component="multer")
    multer_dos = _finding(id="https://github.com/advisories/GHSA-v52c-386h-88mc", component="multer")
    cases.append(
        (
            "excepción por paquete cubre sus advisories",
            _run_case([multer_uno, multer_dos], enforce, por_paquete, today),
            0,
            0,
        )
    )

    # 14. Sin `id` ni `package`, la excepción no dice a qué aplica.
    sin_objetivo = {
        "exceptions": [{"reason": "porque sí", "approved_by": "appsec", "expires_on": date(2026, 10, 1)}]
    }
    cases.append(("excepción sin id ni package es error", _run_case([_finding()], enforce, sin_objetivo, today), 2, 1))

    failures = 0
    for name, report, expected_exit, expected_blocking in cases:
        actual_exit = report.exit_code()
        actual_blocking = len(report.blocking)
        ok = actual_exit == expected_exit and actual_blocking == expected_blocking
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(
            f"[{status}] {name.ljust(42)} exit={actual_exit} (esperado {expected_exit}) "
            f"bloquean={actual_blocking} (esperado {expected_blocking})"
        )

    # Chequeo extra: el parser de severidades de npm audit.
    if normalize_severity("moderate") != "MEDIUM":
        print("[FAIL] npm audit 'moderate' debería mapear a MEDIUM")
        failures += 1
    else:
        print("[PASS] npm audit 'moderate' mapea a MEDIUM".ljust(55))

    print()
    print(f"{len(cases) + 1 - failures}/{len(cases) + 1} casos pasaron")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def load_yaml_file(path: Path) -> dict[str, Any]:
    if not HAVE_YAML:
        raise SystemExit("Falta PyYAML para leer la configuración del gate: pip install pyyaml")
    if not path.is_file():
        raise SystemExit(f"No encuentro {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def collect_finding_files(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        if item.is_dir():
            files += [p for p in item.rglob("*") if p.suffix in {".json", ".sarif"}]
        elif item.is_file():
            files.append(item)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--findings", nargs="*", default=[], type=Path, help="Archivos o carpetas con reportes")
    parser.add_argument("--gate", default=Path("appsec/gate.yaml"), type=Path)
    parser.add_argument("--exceptions", default=Path("appsec/exceptions.yaml"), type=Path)
    parser.add_argument("--out", default="gate-report", help="Basename de salida (.md y .json)")
    parser.add_argument("--today", type=str, default="", help="Fecha de referencia ISO (para pruebas)")
    parser.add_argument("--self-test", action="store_true", help="Corre los casos internos y sale")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    today = parse_date(args.today) or date.today()

    gate_raw = load_yaml_file(args.gate)
    waivers_raw = load_yaml_file(args.exceptions) if args.exceptions.is_file() else {}

    config, config_errors = parse_gate_config(gate_raw)
    waivers, waiver_errors = parse_waivers(waivers_raw, today)

    report = Report(config=config, config_errors=config_errors + waiver_errors)
    findings = load_findings(collect_finding_files(args.findings), report)
    report = build_report(findings, config, waivers, today, report)

    write_outputs(report, args.out)
    print(render_markdown(report))
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
