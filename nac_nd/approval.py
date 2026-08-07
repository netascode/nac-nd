"""Change-approval data collection for pre-change analysis."""

from __future__ import annotations

from typing import Any

from nac_nd.client import NDClient


def prechange_job_details(job: dict[str, Any]) -> dict[str, object]:
    """Extract approval metadata from a completed pre-change job."""
    details: dict[str, object] = {}
    for key in (
        "analysisStatus",
        "analysisScheduleId",
        "baseSnapshotId",
        "uploadedFileName",
        "analysisSubmissionTime",
    ):
        if job.get(key) not in (None, ""):
            details[f"job_{key}"] = job[key]
    return details


def compliance_from_snapshot(
    client: NDClient,
    fabric: str,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compliance summary and violated rules at a snapshot's analysis time."""
    timestamp = str(snapshot.get("analysisTimestamp") or "")
    try:
        summary = client.compliance_summary(
            fabric, collection_timestamp=timestamp or None
        )
        rules = client.compliance_rule_details(
            fabric, collection_timestamp=timestamp or None
        )
    except Exception as exc:
        return {"error": str(exc)}
    return _compliance_payload(summary, rules, requested_timestamp=timestamp)


def _compliance_payload(
    summary: dict[str, Any],
    rules: dict[str, Any],
    *,
    requested_timestamp: str,
) -> dict[str, Any]:
    by_status = summary.get("ruleCountByStatus") or {}
    violated = int(by_status.get("violatedCount", 0) or 0)
    return {
        "scope": "baseline snapshot (before change)",
        "requested_timestamp": requested_timestamp,
        "reported_timestamp": summary.get("collectionTimestamp", ""),
        "enforced_rules": by_status.get("enforcedCount", 0),
        "violated_rules": violated,
        "communication_rules": (summary.get("ruleCountByType") or {}).get(
            "communication", 0
        ),
        "configuration_rules": (summary.get("ruleCountByType") or {}).get(
            "configuration", 0
        ),
        "violating_rules": [
            {
                "ruleName": rule.get("ruleName", ""),
                "ruleType": rule.get("ruleType", ""),
                "violationsCount": rule.get("violationsCount", 0),
            }
            for rule in rules.get("rules") or []
            if int(rule.get("violationsCount", 0) or 0) > 0
        ],
    }
