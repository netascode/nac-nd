"""Verdict computation and output rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET  # nosec B405 — emit JUnit XML only, no parsing

import yaml

from nac_nd.delta import DEFAULT_DELTA_DETAIL, PRECHANGE_DEFAULT_DETAIL
from nac_nd.delta_format import render_delta_detail_text
from nac_nd.exceptions import InputError

# The severity vocabulary `/deltaAnalysis/summary` reports, worst first.
SEVERITIES: tuple[str, ...] = (
    "critical",
    "major",
    "minor",
    "warning",
    "info",
    "unknown",
)

# `info` and `unknown` are excluded, so neither blocks a change on its own.
DEFAULT_FAIL_ON: tuple[str, ...] = ("critical", "major")

OUTPUT_FORMATS: tuple[str, ...] = ("text", "json", "yaml", "markdown", "junit")

_PRECHANGE_IMPACT_FIELDS: tuple[tuple[str, str], ...] = (
    ("New anomalies", "newAnomaliesCount"),
    ("Cleared anomalies", "clearedAnomaliesCount"),
    ("Unchanged anomalies", "unchangedAnomaliesCount"),
    ("Earlier snapshot anomalies", "earlierSnapshotAnomaliesCount"),
    ("Later snapshot anomalies", "laterSnapshotAnomaliesCount"),
)


def parse_fail_on(value: str) -> tuple[str, ...]:
    """Parse a `--fail-on` value into an ordered, validated severity tuple."""
    text = value.strip().lower()
    if text in ("", "none"):
        return ()
    wanted = {part.strip() for part in text.split(",") if part.strip()}
    unknown = sorted(wanted - set(SEVERITIES))
    if unknown:
        raise InputError(
            f"Unknown severity {', '.join(unknown)} in --fail-on. "
            f"Choose from: {', '.join(SEVERITIES)}, or 'none'."
        )
    return tuple(severity for severity in SEVERITIES if severity in wanted)


@dataclass
class Verdict:
    """Whether the new anomalies a change introduced are acceptable."""

    fail_on: tuple[str, ...]
    new_by_severity: dict[str, int]
    total_new: int
    breaching: dict[str, int]

    @property
    def passed(self) -> bool:
        return not self.breaching

    @property
    def reason(self) -> str:
        if self.passed:
            if not self.fail_on:
                return "No severity threshold was set; not evaluated."
            return (
                f"No new {'/'.join(self.fail_on)} anomalies "
                f"({self.total_new} new overall)."
            )
        detail = ", ".join(f"{count} {sev}" for sev, count in self.breaching.items())
        return f"New anomalies at or above the failure threshold: {detail}."

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "fail_on": list(self.fail_on),
            "total_new_anomalies": self.total_new,
            "new_by_severity": self.new_by_severity,
            "breaching": self.breaching,
            "reason": self.reason,
        }


def build_verdict(summary: dict[str, Any], fail_on: tuple[str, ...]) -> Verdict:
    """Decide pass or fail from a `/deltaAnalysis/summary` response.

    The summary reads as all zeros while a job is still running, so the caller
    must have checked the job status first.
    """
    counts: dict[str, int] = {}
    for row in summary.get("anomalyCountBySeverity") or []:
        if not isinstance(row, dict):
            continue
        severity = str(row.get("severity", "")).lower()
        if not severity:
            continue
        counts[severity] = counts.get(severity, 0) + _int(row.get("newCount"))
    ordered = {sev: counts[sev] for sev in SEVERITIES if sev in counts}
    ordered.update({sev: c for sev, c in counts.items() if sev not in SEVERITIES})
    total = sum(ordered.values()) or _int(summary.get("newAnomaliesCount"))
    breaching = {sev: c for sev, c in ordered.items() if sev in fail_on and c > 0}
    return Verdict(
        fail_on=fail_on,
        new_by_severity=ordered,
        total_new=total,
        breaching=breaching,
    )


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class Result:
    """Everything one command produced, ready to render in any format."""

    command: str
    fabric: str
    name: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    anomaly_summary: dict[str, Any] = field(default_factory=dict)
    delta_detail: dict[str, Any] = field(default_factory=dict)
    detail_level: str = ""
    compliance: dict[str, Any] = field(default_factory=dict)
    verdict: Verdict | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "command": self.command,
            "fabric": self.fabric,
            "name": self.name,
            "details": self.details,
        }
        if self.anomaly_summary:
            payload["anomaly_summary"] = self.anomaly_summary
        if self.delta_detail:
            payload["delta_detail"] = self.delta_detail
        if self.compliance:
            payload["compliance"] = self.compliance
        if self.verdict is not None:
            payload["verdict"] = self.verdict.to_dict()
        if self.warnings:
            payload["warnings"] = self.warnings
        return payload


@dataclass
class MultiFabricResult:
    """Aggregated output when ``compliance --all`` runs across several fabrics."""

    command: str
    fabrics: list[Result] = field(default_factory=list)
    failed_fabrics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "fabrics": [item.to_dict() for item in self.fabrics],
            "failed_fabrics": list(self.failed_fabrics),
        }


# -- rendering -------------------------------------------------------------


def render(result: Result, output: str) -> str:
    if output == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=False)
    if output == "yaml":
        dumped: str = yaml.safe_dump(result.to_dict(), sort_keys=False)
        return dumped.rstrip()
    if output == "markdown":
        return _render_markdown(result)
    if output == "junit":
        return _render_junit(result)
    if output == "text":
        if result.command == "prechange":
            return _render_change_approval_text(result)
        return _render_text(result)
    raise InputError(
        f"Unknown output format '{output}'. Choose from: {', '.join(OUTPUT_FORMATS)}."
    )


def render_multi(result: MultiFabricResult, output: str) -> str:
    if output == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=False)
    if output == "yaml":
        dumped: str = yaml.safe_dump(result.to_dict(), sort_keys=False)
        return dumped.rstrip()
    if output == "markdown":
        return _render_multi_markdown(result)
    if output == "junit":
        return _render_multi_junit(result)
    if output == "text":
        return _render_multi_text(result)
    raise InputError(
        f"Unknown output format '{output}'. Choose from: {', '.join(OUTPUT_FORMATS)}."
    )


def _render_multi_text(result: MultiFabricResult) -> str:
    sections = [render(item, "text") for item in result.fabrics]
    lines = sections + [""]
    if result.failed_fabrics:
        lines.append(
            f"FAIL: compliance violations on {', '.join(result.failed_fabrics)}."
        )
    else:
        lines.append("PASS: no compliance violations reported.")
    return "\n\n".join(section for section in lines if section).rstrip()


def _render_multi_markdown(result: MultiFabricResult) -> str:
    sections = [render(item, "markdown") for item in result.fabrics]
    summary = (
        f"**FAIL** — violations on {', '.join(result.failed_fabrics)}."
        if result.failed_fabrics
        else "**PASS** — no compliance violations reported."
    )
    return "\n\n".join(sections + ["", summary])


def _render_multi_junit(result: MultiFabricResult) -> str:
    suites = ET.Element("testsuites", name="nac-nd")
    for item in result.fabrics:
        violated = int(item.compliance.get("violated_rules", 0) or 0)
        classname = f"nac-nd.{item.command}.{item.fabric}"
        suite = ET.SubElement(
            suites,
            "testsuite",
            name=classname,
            tests="1",
            failures="1" if violated else "0",
            errors="0",
            skipped="0",
        )
        case = ET.SubElement(
            suite,
            "testcase",
            classname=classname,
            name="compliance rules",
        )
        if violated:
            ET.SubElement(
                case,
                "failure",
                message=f"{violated} violated rule(s)",
                type="ComplianceViolation",
            )
        properties = ET.SubElement(suite, "properties")
        for key, value in _rows(item):
            ET.SubElement(properties, "property", name=key, value=value)
    ET.indent(suites, space="  ")
    return ET.tostring(suites, encoding="unicode", xml_declaration=True)


def _rows(result: Result) -> list[tuple[str, str]]:
    rows = [("command", result.command), ("fabric", result.fabric)]
    if result.name:
        rows.append(("name", result.name))
    rows += [(key, str(value)) for key, value in result.details.items()]
    return rows


def _item(value: Any) -> str:
    """Render one row of a nested list without using Python's dict repr."""
    if isinstance(value, dict):
        return "  ".join(f"{key}={item}" for key, item in value.items())
    return str(value)


def _render_change_approval_text(result: Result) -> str:
    """Render a change-approval packet suitable for review and sign-off."""
    lines = [
        "=" * 78,
        "CHANGE APPROVAL REPORT — PRE-CHANGE ANALYSIS",
        "=" * 78,
        "",
    ]
    verdict = result.verdict
    if verdict is not None:
        status = "PASS" if verdict.passed else "FAIL"
        lines.append(f"DECISION: {status} — {verdict.reason}")
        lines.append("")

    ui_url = result.details.get("prechange_ui_url")
    if ui_url:
        lines.extend(["Review in Nexus Dashboard:", f"  {ui_url}", ""])

    lines.append("Change context")
    context_rows = [
        ("command", result.command),
        ("fabric", result.fabric),
        ("name", result.name),
    ]
    context_rows += [(key, str(value)) for key, value in result.details.items()]
    for key, value in context_rows:
        if value:
            lines.append(f"  {key:<22} {value}")

    if result.anomaly_summary:
        lines.extend(["", "Impact summary (/deltaAnalysis/summary)", ""])
        for label, field in _PRECHANGE_IMPACT_FIELDS:
            if field in result.anomaly_summary:
                lines.append(f"  {label:<28} {result.anomaly_summary[field]}")
        if verdict is not None:
            lines.extend(["", "New anomalies by severity:", ""])
            if verdict.new_by_severity:
                lines.extend(
                    f"  {severity:<9} {count}"
                    for severity, count in verdict.new_by_severity.items()
                )
            else:
                lines.append("  (none reported)")

    if result.compliance:
        lines.extend(["", "=== Compliance (baseline snapshot) ===", ""])
        compliance = result.compliance
        if "error" in compliance:
            lines.append(f"  error: {compliance['error']}")
        else:
            lines.append(f"  scope: {compliance.get('scope', '')}")
            lines.append(
                f"  enforced: {compliance.get('enforced_rules', 0)}  "
                f"violated: {compliance.get('violated_rules', 0)}"
            )
            violating = compliance.get("violating_rules") or []
            if violating:
                lines.append("  violating rules:")
                for rule in violating:
                    if isinstance(rule, dict):
                        lines.append(
                            "    "
                            f"{rule.get('ruleName', '')} "
                            f"({rule.get('ruleType', '')}) — "
                            f"{rule.get('violationsCount', 0)} violation(s)"
                        )
            else:
                lines.append("  violating rules: (none)")

    if result.delta_detail:
        lines.extend(
            render_delta_detail_text(
                result.delta_detail,
                detail_level=result.detail_level or PRECHANGE_DEFAULT_DETAIL,
                anomaly_summary=result.anomaly_summary or None,
            )
        )

    if result.warnings:
        lines.extend(["", "Warnings", ""])
        lines.extend(f"  warning: {warning}" for warning in result.warnings)

    lines.append("")
    return "\n".join(lines)


def _render_text(result: Result) -> str:
    lines = [f"{key}: {value}" for key, value in _rows(result)]
    if result.verdict is not None:
        lines.append("")
        lines.append("=== Summary (/deltaAnalysis/summary) ===")
        lines.append("")
        lines.append("New anomalies by severity:")
        if result.verdict.new_by_severity:
            lines += [
                f"  {sev:<9} {count}"
                for sev, count in result.verdict.new_by_severity.items()
            ]
        else:
            lines.append("  (none reported)")
        status = "PASS" if result.verdict.passed else "FAIL"
        lines.append("")
        lines.append(f"{status}: {result.verdict.reason}")
    if result.delta_detail:
        lines.extend(
            render_delta_detail_text(
                result.delta_detail,
                detail_level=result.detail_level or DEFAULT_DELTA_DETAIL,
                anomaly_summary=result.anomaly_summary or None,
            )
        )
    if result.compliance:
        lines.append("")
        lines.append("Compliance:")
        for key, value in result.compliance.items():
            if isinstance(value, list):
                lines.append(f"  {key}:")
                lines += [f"    {_item(item)}" for item in value] or ["    (none)"]
            else:
                lines.append(f"  {key}: {value}")
    for warning in result.warnings:
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def _render_markdown(result: Result) -> str:
    lines = [f"# nac-nd {result.command}", ""]
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines += [f"| {key} | {value} |" for key, value in _rows(result)]
    if result.verdict is not None:
        lines += ["", "## New anomalies", "", "| severity | new |", "| --- | --- |"]
        counts = result.verdict.new_by_severity
        if counts:
            lines += [f"| {sev} | {count} |" for sev, count in counts.items()]
        else:
            lines.append("| (none reported) | 0 |")
        status = "**PASS**" if result.verdict.passed else "**FAIL**"
        lines += ["", f"{status} — {result.verdict.reason}"]
    if result.compliance:
        lines += ["", "## Compliance", "", "| field | value |", "| --- | --- |"]
        lines += [f"| {key} | {value} |" for key, value in result.compliance.items()]
    if result.warnings:
        lines += ["", "## Warnings", ""]
        lines += [f"- {warning}" for warning in result.warnings]
    return "\n".join(lines)


def _render_junit(result: Result) -> str:
    """Render a JUnit XML report.

    One test case per severity in `--fail-on`, so a CI front end shows which
    severity broke the build. Built with ElementTree so API-supplied text
    cannot produce malformed XML.
    """
    classname = f"nac-nd.{result.command}.{result.fabric or 'unknown'}"
    cases: list[tuple[str, str]] = []
    verdict = result.verdict
    if verdict is not None:
        for severity in verdict.fail_on or SEVERITIES:
            count = verdict.new_by_severity.get(severity, 0)
            failure = (
                f"{count} new {severity} anomal{'y' if count == 1 else 'ies'}"
                if severity in verdict.breaching
                else ""
            )
            cases.append((f"no new {severity} anomalies", failure))
    if not cases:
        cases.append((result.command, ""))

    failures = sum(1 for _, failure in cases if failure)
    suites = ET.Element("testsuites", name="nac-nd")
    suite = ET.SubElement(
        suites,
        "testsuite",
        name=classname,
        tests=str(len(cases)),
        failures=str(failures),
        errors="0",
        skipped="0",
    )
    for name, failure in cases:
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if failure:
            ET.SubElement(case, "failure", message=failure, type="AnomalyThreshold")
    properties = ET.SubElement(suite, "properties")
    for key, value in _rows(result):
        ET.SubElement(properties, "property", name=key, value=value)
    ET.indent(suites, space="  ")
    return ET.tostring(suites, encoding="unicode", xml_declaration=True)
