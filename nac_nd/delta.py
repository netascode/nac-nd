"""Collect delta-analysis detail from Nexus Dashboard (domain layer)."""

from __future__ import annotations

from typing import Any

from nac_nd.client import NDClient
from nac_nd.exceptions import InputError

DEFAULT_DELTA_DETAIL = "resources"
PRECHANGE_DEFAULT_DETAIL = "full"

DELTA_DETAIL_LEVELS: tuple[str, ...] = (
    "none",
    "resources",
    "anomalies",
    "policy-diff",
    "full",
)

# Accepted for backwards compatibility; normalised before use.
_DELTA_DETAIL_ALIASES: dict[str, str] = {
    "all": "full",
    "summary": "none",
}


def normalize_delta_detail(value: str) -> str:
    """Normalise a ``--detail`` value, including legacy names."""
    text = value.strip().lower()
    return _DELTA_DETAIL_ALIASES.get(text, text)


def parse_delta_detail(value: str) -> frozenset[str]:
    """Return which extra endpoints to call (never includes summary)."""
    level = normalize_delta_detail(value)
    if level == "full":
        return frozenset({"resources", "anomalies", "policy-diff"})
    if level == "none":
        return frozenset()
    if level not in DELTA_DETAIL_LEVELS:
        raise InputError(
            f"Unknown --detail value '{value}'. "
            f"Choose from: {', '.join(DELTA_DETAIL_LEVELS)}."
        )
    return frozenset({level})


def summary_new_count(summary: dict[str, Any]) -> int:
    """Return the number of new anomalies reported by ``/deltaAnalysis/summary``."""
    total = 0
    for row in summary.get("anomalyCountBySeverity") or []:
        if isinstance(row, dict):
            total += int(row.get("newCount") or 0)
    if total == 0:
        total = int(summary.get("newAnomaliesCount") or 0)
    return total


def fetch_delta_details(
    client: NDClient,
    *,
    fabric: str,
    job_id: str,
    detail: str,
    include_acknowledged: bool,
) -> dict[str, Any]:
    """Call the selected detail endpoints and return raw payloads or errors."""
    sections = parse_delta_detail(detail)
    payloads: dict[str, Any] = {}
    if "resources" in sections:
        payloads["resources"] = _safe_call(
            client.delta_resources,
            job_id,
            include_acknowledged=include_acknowledged,
        )
    if "anomalies" in sections:
        payloads["anomalies"] = _safe_call(
            client.anomaly_details,
            fabric,
            job_id=job_id,
            include_acknowledged=include_acknowledged,
        )
    if "policy-diff" in sections:
        payloads["policy_diff"] = _safe_call(client.delta_policy_diff, job_id)
    return payloads


def collect_delta_detail_warnings(
    delta_detail: dict[str, Any], *, anomaly_summary: dict[str, Any]
) -> list[str]:
    """Return user-visible warnings about detail payloads."""
    warnings: list[str] = []
    block = delta_detail.get("anomalies")
    if not block or "error" in block:
        return warnings
    data = block.get("data")
    if not isinstance(data, dict):
        return warnings
    records = [item for item in data.get("anomalies") or [] if isinstance(item, dict)]
    expected = summary_new_count(anomaly_summary)
    if expected and len(records) != expected:
        warnings.append(
            f"anomalies/details returned {len(records)} record(s) but summary "
            f"reports {expected} new — the list may include fabric-wide state, "
            "not delta-only anomalies."
        )
    return warnings


def _safe_call(method: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return {
            "endpoint": _endpoint_label(method.__name__),
            "data": method(*args, **kwargs),
        }
    except Exception as exc:
        return {"endpoint": _endpoint_label(method.__name__), "error": str(exc)}


def _endpoint_label(method_name: str) -> str:
    return {
        "delta_resources": "/deltaAnalysis/resources",
        "anomaly_details": "/anomalies/details",
        "delta_policy_diff": "/deltaAnalysis/policyDiff",
    }.get(method_name, method_name)
