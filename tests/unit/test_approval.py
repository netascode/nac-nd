"""Change-approval data collection."""

from __future__ import annotations

from nac_nd.approval import compliance_from_snapshot, prechange_job_details
from tests.conftest import Lab, json_response

SUMMARY_PATH = "/api/v1/analyze/complianceReport/summary"
RULES_PATH = "/api/v1/analyze/complianceReport/ruleDetails"


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


def test_compliance_from_snapshot_returns_violating_rules(make_client) -> None:
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
                    ]
                }
            ),
        }
    )
    client = make_client(lab)
    snapshot = {"analysisTimestamp": "2026-08-07T10:39:54Z"}

    payload = compliance_from_snapshot(client, "FABRIC-A", snapshot)

    assert payload["violated_rules"] == 1
    assert payload["violating_rules"] == [
        {
            "ruleName": "rule-a",
            "ruleType": "configuration",
            "violationsCount": 1,
        }
    ]


def test_compliance_from_snapshot_surfaces_api_errors(make_client) -> None:
    lab = Lab({SUMMARY_PATH: json_response({"message": "boom"}, 500)})
    client = make_client(lab)

    payload = compliance_from_snapshot(client, "FABRIC-A", {})

    assert "error" in payload
