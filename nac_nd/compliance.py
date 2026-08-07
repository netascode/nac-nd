"""Compliance rule summaries and pre-change job metadata (domain layer)."""

from __future__ import annotations

from typing import Any

from nac_nd.client import NDClient
from nac_nd.report import Result


def snapshot_details(label: str, snapshot: dict[str, object]) -> dict[str, object]:
    """Snapshot id and collection time for command result details."""
    return {
        f"{label}_snapshot_id": snapshot.get("snapshotId", ""),
        f"{label}_collected_at": snapshot.get("collectionTimestamp", ""),
    }


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


def compliance_payload(
    summary: dict[str, Any],
    rules: dict[str, Any],
    *,
    scope: str = "",
    requested_timestamp: str = "",
) -> dict[str, Any]:
    """Normalise summary and rule-details API responses into one compliance dict."""
    by_status = summary.get("ruleCountByStatus") or {}
    violated = int(by_status.get("violatedCount", 0) or 0)
    payload: dict[str, Any] = {
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
    if scope:
        payload["scope"] = scope
    if requested_timestamp:
        payload["requested_timestamp"] = requested_timestamp
    return payload


def compliance_for_snapshot(
    client: NDClient,
    fabric: str,
    snapshot: dict[str, Any],
    *,
    scope: str,
) -> dict[str, Any]:
    """Compliance summary and violated rules at a snapshot's analysis time."""
    timestamp = str(snapshot.get("analysisTimestamp") or "")
    summary = client.compliance_summary(fabric, collection_timestamp=timestamp or None)
    rules = client.compliance_rule_details(
        fabric, collection_timestamp=timestamp or None
    )
    return compliance_payload(
        summary,
        rules,
        scope=scope,
        requested_timestamp=timestamp,
    )


def run_compliance_check(
    client: NDClient,
    fabric: str,
    *,
    snapshot: str | None,
    since: str | None,
    until: str | None,
) -> tuple[Result, int]:
    """Build a compliance command ``Result`` and violated rule count."""
    details: dict[str, object] = {}
    timestamp: str | None = None
    if snapshot:
        record = client.resolve_snapshot(
            fabric, snapshot, start_date=since, end_date=until
        )
        timestamp = str(record.get("analysisTimestamp", ""))
        details.update(snapshot_details("selected", record))
        details["requested_timestamp"] = timestamp
    summary = client.compliance_summary(fabric, collection_timestamp=timestamp)
    rules = client.compliance_rule_details(fabric, collection_timestamp=timestamp)
    details["reported_timestamp"] = summary.get("collectionTimestamp", "")
    compliance = compliance_payload(summary, rules)
    violated = int(compliance.get("violated_rules", 0) or 0)
    result = Result(
        command="compliance",
        fabric=fabric,
        details=details,
        compliance=compliance,
    )
    return result, violated
