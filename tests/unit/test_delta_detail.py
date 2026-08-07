"""Delta detail fetching and rendering."""

from __future__ import annotations

import pytest

from nac_nd.delta_detail import (
    collect_delta_detail_warnings,
    fetch_delta_details,
    normalize_delta_detail,
    parse_delta_detail,
    render_delta_detail_text,
    summary_new_count,
)
from nac_nd.exceptions import InputError


def test_parse_delta_detail_accepts_full_and_none() -> None:
    assert parse_delta_detail("full") == frozenset(
        {"resources", "anomalies", "policy-diff"}
    )
    assert parse_delta_detail("none") == frozenset()


def test_legacy_detail_names_still_work() -> None:
    assert parse_delta_detail("all") == parse_delta_detail("full")
    assert parse_delta_detail("summary") == parse_delta_detail("none")
    assert normalize_delta_detail("ALL") == "full"


def test_an_unknown_detail_level_is_bad_input() -> None:
    with pytest.raises(InputError, match="Unknown --detail"):
        parse_delta_detail("verbose")


def test_nested_resources_render_as_columns() -> None:
    lines = render_delta_detail_text(
        {
            "resources": {
                "endpoint": "/deltaAnalysis/resources",
                "data": {
                    "resources": [
                        {
                            "resourceType": "tenant",
                            "healthy": {
                                "earlierCount": 112,
                                "laterCount": 113,
                                "newCount": 1,
                                "removedCount": 0,
                                "unchangedCount": 112,
                            },
                            "unhealthy": {
                                "earlierCount": 13,
                                "laterCount": 13,
                                "newCount": 0,
                                "removedCount": 0,
                                "unchangedCount": 13,
                            },
                            "total": {
                                "earlierCount": 125,
                                "laterCount": 126,
                                "newCount": 1,
                                "removedCount": 0,
                                "unchangedCount": 125,
                            },
                        },
                        {
                            "resourceType": "vlan",
                            "total": {
                                "earlierCount": 10,
                                "laterCount": 10,
                                "newCount": 0,
                                "removedCount": 0,
                                "unchangedCount": 10,
                            },
                        },
                    ]
                },
            }
        },
        detail_level="resources",
    )

    text = "\n".join(lines)
    assert "tenant" in text
    assert "vlan" not in text
    assert "unchanged resource type(s) hidden" in text
    assert "{'earlierCount'" not in text


def test_full_detail_shows_unchanged_resource_types() -> None:
    lines = render_delta_detail_text(
        {
            "resources": {
                "endpoint": "/deltaAnalysis/resources",
                "data": {
                    "resources": [
                        {
                            "resourceType": "vlan",
                            "total": {
                                "earlierCount": 10,
                                "laterCount": 10,
                                "newCount": 0,
                                "removedCount": 0,
                                "unchangedCount": 10,
                            },
                        }
                    ]
                },
            }
        },
        detail_level="full",
    )

    assert "vlan" in "\n".join(lines)


def test_anomalies_render_mnemonic_rows_and_mismatch_hint() -> None:
    summary = {
        "anomalyCountBySeverity": [
            {"severity": "major", "newCount": 2},
        ]
    }
    lines = render_delta_detail_text(
        {
            "anomalies": {
                "endpoint": "/anomalies/details",
                "data": {
                    "anomalies": [
                        {
                            "severity": "major",
                            "mnemonicTitle": "ENDPOINT_DUPLICATE_IP",
                            "resourceName": "web-epg",
                            "anomalyReason": "duplicate ip detected",
                        },
                        {
                            "severity": "major",
                            "mnemonicTitle": "ENDPOINT_DUPLICATE_IP",
                            "resourceName": "web-epg",
                            "anomalyReason": "duplicate ip detected",
                        },
                        {
                            "severity": "warning",
                            "mnemonicTitle": "OTHER",
                            "resourceName": "db-epg",
                            "anomalyReason": "something else",
                        },
                    ],
                    "meta": {"counts": {"total": 3, "remaining": 0}},
                },
            }
        },
        detail_level="anomalies",
        anomaly_summary=summary,
    )

    text = "\n".join(lines)
    assert "ENDPOINT_DUPLICATE_IP" in text
    assert "duplicate ip detected" in text
    assert "duplicate row(s) collapsed" in text
    assert "summary reports 2 new anomalies" in text


def test_collect_delta_detail_warnings() -> None:
    warnings = collect_delta_detail_warnings(
        {
            "anomalies": {
                "data": {"anomalies": [{"severity": "major"}, {"severity": "major"}]}
            }
        },
        anomaly_summary={
            "anomalyCountBySeverity": [{"severity": "major", "newCount": 1}]
        },
    )
    assert len(warnings) == 1
    assert "summary reports 1 new" in warnings[0]


def test_policy_diff_shows_changed_lines_only() -> None:
    lines = render_delta_detail_text(
        {
            "policy_diff": {
                "endpoint": "/deltaAnalysis/policyDiff",
                "data": {
                    "lines": [
                        {"changeType": "unchanged", "lineContent": "  tenant { ... }"},
                        {"changeType": "added", "lineContent": "  epg new-epg { ... }"},
                    ]
                },
            }
        },
        detail_level="policy-diff",
    )

    text = "\n".join(lines)
    assert "[added]" in text
    assert "unchanged" not in text.split("[added]")[0]


def test_summary_new_count_sums_severity_rows() -> None:
    assert (
        summary_new_count(
            {"anomalyCountBySeverity": [{"newCount": 3}, {"newCount": 5}]}
        )
        == 8
    )


def test_fetch_delta_details_calls_only_selected_endpoints(make_client) -> None:
    from tests.conftest import Lab, json_response

    lab = Lab(
        {
            "/api/v1/analyze/deltaAnalysis/resources": json_response({"resources": []}),
            "/api/v1/analyze/anomalies/details": json_response({"anomalies": []}),
            "/api/v1/analyze/deltaAnalysis/policyDiff": json_response({"imdata": []}),
        }
    )
    client = make_client(lab)

    fetch_delta_details(
        client,
        fabric="FABRIC-A",
        job_id="job-1",
        detail="resources",
        include_acknowledged=False,
    )

    assert len(lab.requests_to("/api/v1/analyze/deltaAnalysis/resources")) == 1
    assert lab.requests_to("/api/v1/analyze/anomalies/details") == []
    assert lab.requests_to("/api/v1/analyze/deltaAnalysis/policyDiff") == []


def test_render_surfaces_endpoint_errors() -> None:
    lines = render_delta_detail_text(
        {
            "policy_diff": {
                "endpoint": "/deltaAnalysis/policyDiff",
                "error": "HTTP 404",
            }
        },
        detail_level="policy-diff",
    )

    assert "error: HTTP 404" in "\n".join(lines)


def test_policy_diff_without_lines_falls_back_to_preview() -> None:
    lines = render_delta_detail_text(
        {
            "policy_diff": {
                "endpoint": "/deltaAnalysis/policyDiff",
                "data": {"changeCount": 0, "summary": "no textual diff"},
            }
        },
        detail_level="policy-diff",
    )

    text = "\n".join(lines)
    assert "top-level keys:" in text
    assert "changeCount" in text
