"""Verdict computation and output rendering."""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

import pytest
import yaml

from nac_nd.exceptions import InputError
from nac_nd.report import (
    DEFAULT_FAIL_ON,
    OUTPUT_FORMATS,
    MultiFabricResult,
    Result,
    build_verdict,
    parse_fail_on,
    render,
    render_multi,
)


def summary(**counts: int) -> dict:
    return {
        "newAnomaliesCount": sum(counts.values()),
        "anomalyCountBySeverity": [
            {"severity": severity, "newCount": count, "clearedCount": 0}
            for severity, count in counts.items()
        ],
    }


def test_the_verdict_counts_only_new_anomalies() -> None:
    verdict = build_verdict(summary(critical=2, minor=7), DEFAULT_FAIL_ON)

    assert verdict.total_new == 9
    assert verdict.breaching == {"critical": 2}
    assert verdict.passed is False


def test_info_and_unknown_do_not_fail_a_run_by_default() -> None:
    """`info` and `unknown` are outside the default threshold."""
    verdict = build_verdict(summary(info=40, unknown=3), DEFAULT_FAIL_ON)

    assert verdict.passed is True
    assert verdict.total_new == 43


def test_severities_are_reported_worst_first() -> None:
    verdict = build_verdict(summary(minor=1, critical=1, warning=1), DEFAULT_FAIL_ON)

    assert list(verdict.new_by_severity) == ["critical", "minor", "warning"]


def test_thresholds_can_be_widened_or_switched_off() -> None:
    counts = summary(minor=3)

    assert build_verdict(counts, parse_fail_on("critical,major,minor")).passed is False
    assert build_verdict(counts, parse_fail_on("none")).passed is True
    assert build_verdict(counts, parse_fail_on("")).passed is True


def test_an_unknown_severity_is_bad_input() -> None:
    with pytest.raises(InputError) as caught:
        parse_fail_on("critical,catastrophic")

    assert caught.value.exit_code == 4
    assert "catastrophic" in str(caught.value)


def test_severity_names_are_normalised() -> None:
    assert parse_fail_on(" MAJOR , critical ") == ("critical", "major")


def test_a_summary_with_no_severity_rows_falls_back_to_the_total() -> None:
    verdict = build_verdict({"newAnomaliesCount": 5}, DEFAULT_FAIL_ON)

    assert verdict.total_new == 5
    assert verdict.passed is True


def result(**overrides: object) -> Result:
    payload = {
        "command": "prechange",
        "fabric": "FABRIC-A",
        "name": "run-1",
        "details": {"job_id": "abc123"},
        "anomaly_summary": summary(critical=1),
        "verdict": build_verdict(summary(critical=1), DEFAULT_FAIL_ON),
    }
    payload.update(overrides)
    return Result(**payload)  # type: ignore[arg-type]


@pytest.mark.parametrize("output", OUTPUT_FORMATS)
def test_every_format_renders(output: str) -> None:
    assert render(result(), output).strip()


def test_json_output_round_trips() -> None:
    payload = json.loads(render(result(), "json"))

    assert payload["verdict"]["passed"] is False
    assert payload["verdict"]["breaching"] == {"critical": 1}


def test_yaml_output_round_trips() -> None:
    payload = yaml.safe_load(render(result(), "yaml"))

    assert payload["fabric"] == "FABRIC-A"


def test_text_output_states_the_verdict() -> None:
    text = render(result(), "text")

    assert "DECISION: FAIL" in text
    assert "CHANGE APPROVAL REPORT" in text
    assert "critical" in text


def test_junit_reports_one_case_per_threshold_severity() -> None:
    root = ET.fromstring(render(result(), "junit"))
    suite = root.find("testsuite")

    assert suite is not None
    assert suite.get("tests") == "2"
    assert suite.get("failures") == "1"
    failed = [
        case.get("name")
        for case in suite.findall("testcase")
        if case.find("failure") is not None
    ]
    assert failed == ["no new critical anomalies"]


def test_junit_escapes_api_supplied_text() -> None:
    """Values come from API responses, so the XML is built, not formatted."""
    rendered = render(result(details={"job_id": '<bad & "quoted">'}), "junit")

    ET.fromstring(rendered)
    assert "&amp;" in rendered


def test_an_unknown_output_format_is_bad_input() -> None:
    with pytest.raises(InputError) as caught:
        render(result(), "toml")

    assert caught.value.exit_code == 4


def compliance_result(fabric: str, *, violated: int) -> Result:
    return Result(
        command="compliance",
        fabric=fabric,
        compliance={
            "enforced_rules": 10,
            "violated_rules": violated,
            "violating_rules": [{"ruleName": "r1", "violationsCount": violated}]
            if violated
            else [],
        },
    )


def test_text_output_includes_delta_detail_compliance_and_warnings() -> None:
    text = render(
        result(
            delta_detail={
                "resources": {
                    "endpoint": "/deltaAnalysis/resources",
                    "error": "HTTP 503",
                }
            },
            detail_level="resources",
            compliance={"violated_rules": 2, "violating_rules": []},
            warnings=["delta job survived cleanup"],
        ),
        "text",
    )

    assert "error: HTTP 503" in text
    assert "Compliance (baseline snapshot)" in text
    assert "violated: 2" in text
    assert "warning: delta job survived cleanup" in text


def test_prechange_text_uses_change_approval_report() -> None:
    text = render(
        result(
            details={
                "job_id": "abc123",
                "base_snapshot_id": "snap-1",
                "prechange_ui_url": (
                    "https://nd.example.com/appcenter/cisco/nexus-insights/ui/"
                    "#/changeManagement/preChangeAnalysis"
                ),
            },
            anomaly_summary={
                "newAnomaliesCount": 2,
                "clearedAnomaliesCount": 0,
            },
            compliance={
                "scope": "baseline snapshot (before change)",
                "enforced_rules": 10,
                "violated_rules": 1,
                "violating_rules": [
                    {
                        "ruleName": "no-open-tenant",
                        "ruleType": "configuration",
                        "violationsCount": 1,
                    }
                ],
            },
            delta_detail={
                "resources": {
                    "endpoint": "/deltaAnalysis/resources",
                    "addedCount": 1,
                    "removedCount": 0,
                }
            },
            detail_level="full",
        ),
        "text",
    )

    assert "CHANGE APPROVAL REPORT" in text
    assert "Review in Nexus Dashboard:" in text
    assert "preChangeAnalysis" in text
    assert "Change context" in text
    assert "Impact summary (/deltaAnalysis/summary)" in text
    assert "no-open-tenant" in text
    assert "New anomalies" in text


def test_delta_text_keeps_compact_format() -> None:
    text = render(
        result(
            command="delta",
            compliance={"violated_rules": 2},
            warnings=["acknowledged anomalies included"],
        ),
        "text",
    )

    assert "CHANGE APPROVAL REPORT" not in text
    assert "Compliance:" in text
    assert "command: delta" in text


def test_markdown_output_includes_compliance_and_warnings() -> None:
    text = render(
        result(
            compliance={"violated_rules": 1},
            warnings=["acknowledged anomalies included"],
        ),
        "markdown",
    )

    assert "## Compliance" in text
    assert "## Warnings" in text
    assert "acknowledged anomalies included" in text


def test_pass_verdict_with_no_severity_rows() -> None:
    text = render(
        result(
            anomaly_summary={"newAnomaliesCount": 0},
            verdict=build_verdict({"newAnomaliesCount": 0}, DEFAULT_FAIL_ON),
        ),
        "text",
    )

    assert "DECISION: PASS" in text
    assert "(none reported)" in text


def test_multi_fabric_text_reports_failures() -> None:
    multi = MultiFabricResult(
        command="compliance",
        fabrics=[
            compliance_result("FABRIC-A", violated=0),
            compliance_result("FABRIC-B", violated=3),
        ],
        failed_fabrics=["FABRIC-B"],
    )

    text = render_multi(multi, "text")

    assert "FABRIC-A" in text
    assert "FABRIC-B" in text
    assert "FAIL: compliance violations on FABRIC-B." in text


def test_multi_fabric_junit_has_one_suite_per_fabric() -> None:
    multi = MultiFabricResult(
        command="compliance",
        fabrics=[
            compliance_result("FABRIC-A", violated=0),
            compliance_result("FABRIC-B", violated=1),
        ],
        failed_fabrics=["FABRIC-B"],
    )

    root = ET.fromstring(render_multi(multi, "junit"))

    assert len(root.findall("testsuite")) == 2
    failures = sum(
        1
        for suite in root.findall("testsuite")
        for case in suite.findall("testcase")
        if case.find("failure") is not None
    )
    assert failures == 1


def test_multi_fabric_unknown_output_format_is_bad_input() -> None:
    multi = MultiFabricResult(
        command="compliance",
        fabrics=[compliance_result("X", violated=0)],
    )

    with pytest.raises(InputError):
        render_multi(multi, "toml")
