"""Delta detail text rendering."""

from __future__ import annotations

from nac_nd.delta_format import render_delta_detail_text


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
