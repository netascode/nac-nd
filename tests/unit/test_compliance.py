"""Compliance reporting and timestamp verification."""

from __future__ import annotations

import pytest

from nac_nd.client import check_compliance_timestamp, compliance_timestamp_drift
from nac_nd.compliance import compliance_for_snapshot, prechange_job_details
from nac_nd.exceptions import ApiError
from tests.conftest import Lab, json_response

SUMMARY_PATH = "/api/v1/analyze/complianceReport/summary"
RULES_PATH = "/api/v1/analyze/complianceReport/ruleDetails"

# A snapshot collected at 10:38:56 whose assurance analysis landed at
# 10:39:54. The compliance run lands with the analysis.
SNAPSHOT = {
    "snapshotId": "snap-1",
    "collectionTimestamp": "2026-08-07T10:38:56Z",
    "analysisTimestamp": "2026-08-07T10:39:54Z",
}

HEALTHY_ZEROS = {
    "collectionTimestamp": "2026-08-07T10:39:54Z",
    "ruleCountByStatus": {"enforcedCount": 0, "violatedCount": 0},
    "ruleCountByType": {"communication": 0, "configuration": 0},
}


def test_the_analysis_timestamp_is_the_one_that_lands_correctly(make_client) -> None:
    """The parameter is an inclusive upper bound, so `analysisTimestamp` is sent.

    A compliance run completes about a minute after the snapshot's
    `collectionTimestamp`, which would resolve to the previous collection.
    """
    lab = Lab({SUMMARY_PATH: json_response(HEALTHY_ZEROS)})
    client = make_client(lab)

    client.compliance_summary(
        "FABRIC-A", collection_timestamp=SNAPSHOT["analysisTimestamp"]
    )

    asked = lab.requests_to(SUMMARY_PATH)[0].url.params["collectionTimestamp"]
    assert asked == "2026-08-07T10:39:54Z"
    assert asked != SNAPSHOT["collectionTimestamp"]


def test_a_meaningless_timestamp_returns_a_fabricated_clean_bill_of_health(
    make_client,
) -> None:
    """A meaningless timestamp returns HTTP 200 with every count at zero."""
    lab = Lab({SUMMARY_PATH: json_response(HEALTHY_ZEROS)})
    client = make_client(lab)

    with pytest.raises(ApiError) as caught:
        client.compliance_summary(
            "FABRIC-A", collection_timestamp="1999-01-01T00:00:00Z"
        )

    assert "different compliance collection" in str(caught.value)


def test_the_report_does_not_echo_the_requested_timestamp_back() -> None:
    """The request resolves to the nearest collection, which may be far away."""
    report = {"collectionTimestamp": "2026-08-07T08:39:54Z"}

    with pytest.raises(ApiError, match="7200s away"):
        check_compliance_timestamp("2026-08-07T10:39:54Z", report)


def test_a_small_drift_is_accepted() -> None:
    """A compliance run lands about a minute after the snapshot."""
    check_compliance_timestamp(
        "2026-08-07T10:39:54Z", {"collectionTimestamp": "2026-08-07T10:40:52Z"}
    )


def test_an_unparseable_timestamp_is_refused_rather_than_trusted() -> None:
    with pytest.raises(ApiError, match="Could not verify"):
        check_compliance_timestamp("2026-08-07T10:39:54Z", {})


def test_drift_handles_the_z_suffix_and_offsets() -> None:
    same_moment = compliance_timestamp_drift(
        "2026-08-07T10:00:00Z", "2026-08-07T11:00:00+01:00"
    )

    assert same_moment == 0.0
    assert compliance_timestamp_drift("not-a-time", "2026-08-07T10:00:00Z") is None


def test_an_unscoped_report_is_not_timestamp_checked(make_client) -> None:
    """Without a requested timestamp there is nothing to compare against."""
    lab = Lab({SUMMARY_PATH: json_response({"collectionTimestamp": "whenever"})})
    client = make_client(lab)

    assert client.compliance_summary("FABRIC-A")["collectionTimestamp"] == "whenever"
    assert "collectionTimestamp" not in lab.requests_to(SUMMARY_PATH)[0].url.params


def test_rule_details_are_verified_too(make_client) -> None:
    stale = json_response({"collectionTimestamp": "1999-01-01T00:00:00Z"})
    lab = Lab({RULES_PATH: stale})
    client = make_client(lab)

    with pytest.raises(ApiError):
        client.compliance_rule_details(
            "FABRIC-A", collection_timestamp="2026-08-07T10:39:54Z"
        )


def test_prechange_job_details_extracts_known_fields() -> None:
    job = {
        "analysisStatus": "completed",
        "analysisScheduleId": "sched-1",
        "baseSnapshotId": "snap-1",
        "uploadedFileName": "plan.json",
        "analysisSubmissionTime": "2026-08-07T10:00:00Z",
        "ignored": "",
    }

    details = prechange_job_details(job)

    assert details == {
        "job_analysisStatus": "completed",
        "job_analysisScheduleId": "sched-1",
        "job_baseSnapshotId": "snap-1",
        "job_uploadedFileName": "plan.json",
        "job_analysisSubmissionTime": "2026-08-07T10:00:00Z",
    }


def test_compliance_for_snapshot_returns_violating_rules(make_client) -> None:
    lab = Lab(
        {
            SUMMARY_PATH: json_response(
                {
                    "collectionTimestamp": "2026-08-07T10:39:54Z",
                    "ruleCountByStatus": {
                        "enforcedCount": 5,
                        "violatedCount": 1,
                    },
                    "ruleCountByType": {
                        "communication": 2,
                        "configuration": 3,
                    },
                }
            ),
            RULES_PATH: json_response(
                {
                    "collectionTimestamp": "2026-08-07T10:39:54Z",
                    "rules": [
                        {
                            "ruleName": "rule-a",
                            "ruleType": "configuration",
                            "violationsCount": 1,
                        },
                        {
                            "ruleName": "rule-b",
                            "ruleType": "communication",
                            "violationsCount": 0,
                        },
                    ],
                }
            ),
        }
    )
    client = make_client(lab)
    snapshot = {"analysisTimestamp": "2026-08-07T10:39:54Z"}

    payload = compliance_for_snapshot(
        client,
        "FABRIC-A",
        snapshot,
        scope="baseline snapshot (before change)",
    )

    assert payload["violated_rules"] == 1
    assert payload["scope"] == "baseline snapshot (before change)"
    assert payload["violating_rules"] == [
        {
            "ruleName": "rule-a",
            "ruleType": "configuration",
            "violationsCount": 1,
        }
    ]


def test_compliance_for_snapshot_propagates_api_errors(make_client) -> None:
    lab = Lab({SUMMARY_PATH: json_response({"message": "boom"}, 500)})
    client = make_client(lab)

    with pytest.raises(ApiError):
        compliance_for_snapshot(client, "FABRIC-A", {}, scope="test")
