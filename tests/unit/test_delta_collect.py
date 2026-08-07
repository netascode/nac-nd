"""Delta detail collection from Nexus Dashboard (fetch and parse)."""

from __future__ import annotations

import pytest

from nac_nd.delta import (
    collect_delta_detail_warnings,
    fetch_delta_details,
    normalize_delta_detail,
    parse_delta_detail,
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
