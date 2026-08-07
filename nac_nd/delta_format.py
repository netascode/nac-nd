"""Format delta-analysis detail payloads for terminal output (reporting layer)."""

from __future__ import annotations

import json
from typing import Any

from nac_nd.delta import normalize_delta_detail, summary_new_count

_POLICY_DIFF_CAP = 20
_ANOMALY_ROW_CAP = 50


def render_delta_detail_text(
    delta_detail: dict[str, Any],
    *,
    detail_level: str,
    anomaly_summary: dict[str, Any] | None = None,
) -> list[str]:
    """Render fetched detail payloads for terminal output."""
    level = normalize_delta_detail(detail_level)
    show_all_resources = level == "full"
    lines: list[str] = []
    order = (
        ("resources", "Resources", "/deltaAnalysis/resources"),
        ("anomalies", "Anomalies", "/anomalies/details"),
        ("policy_diff", "Policy diff", "/deltaAnalysis/policyDiff"),
    )
    for key, title, endpoint in order:
        block = delta_detail.get(key)
        if block is None:
            continue
        lines.extend(["", f"=== {title} ({endpoint}) ==="])
        if "error" in block:
            lines.append(f"error: {block['error']}")
            continue
        data = block.get("data")
        if key == "resources":
            lines.extend(_render_resources(data, show_all=show_all_resources))
        elif key == "anomalies":
            lines.extend(_render_anomalies(data, anomaly_summary=anomaly_summary))
        else:
            lines.extend(_render_policy_diff(data))
    return lines


def _bucket_count(bucket: Any, field: str) -> int:
    if isinstance(bucket, dict):
        return int(bucket.get(field) or 0)
    if isinstance(bucket, (int, float)):
        return int(bucket)
    return 0


def _normalize_resource_row(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested healthy/unhealthy/total objects from the GA API."""
    total = raw.get("total")
    unhealthy = raw.get("unhealthy")
    if isinstance(total, dict) or isinstance(unhealthy, dict):
        return {
            "resourceType": str(
                raw.get("resourceType") or raw.get("type") or raw.get("name") or ""
            ),
            "new": _bucket_count(total, "newCount"),
            "removed": _bucket_count(total, "removedCount"),
            "earlier": _bucket_count(total, "earlierCount"),
            "later": _bucket_count(total, "laterCount"),
            "unhealthy": _bucket_count(unhealthy, "laterCount"),
        }
    return {
        "resourceType": str(
            raw.get("resourceType") or raw.get("type") or raw.get("name") or ""
        ),
        "new": int(raw.get("new") or raw.get("newCount") or 0),
        "removed": int(raw.get("removed") or raw.get("removedCount") or 0),
        "earlier": int(raw.get("earlier") or raw.get("earlierCount") or 0),
        "later": int(raw.get("later") or raw.get("laterCount") or 0),
        "unhealthy": int(raw.get("unhealthy") or raw.get("unhealthyCount") or 0),
    }


def _resource_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    for key in ("resources", "resourceCounts", "resourceSummary", "entries"):
        items = data.get(key)
        if isinstance(items, list):
            return [
                _normalize_resource_row(item)
                for item in items
                if isinstance(item, dict)
            ]
    return []


def _render_resources(data: Any, *, show_all: bool) -> list[str]:
    rows = _resource_rows(data)
    if not rows:
        return ["  (no resource rows returned)", _preview_json(data)]
    changed = [row for row in rows if row["new"] or row["removed"]]
    visible = rows if show_all else changed
    if not visible:
        return ["  (no resource types with new or removed objects)"]
    columns = ("resourceType", "new", "removed", "earlier", "later", "unhealthy")
    header = "  ".join(f"{col:>12}" for col in columns)
    lines = [header]
    for row in visible:
        lines.append("  ".join(f"{str(row.get(col, '')):>12}" for col in columns))
    if not show_all and len(changed) < len(rows):
        hidden = len(rows) - len(changed)
        lines.append(
            f"  ({hidden} unchanged resource type(s) hidden; "
            "use --detail full to show all)"
        )
    return lines


def _anomaly_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    reason = str(record.get("anomalyReason") or record.get("anomalyString") or "")
    return (
        str(record.get("severity", "")),
        str(record.get("mnemonicTitle") or record.get("anomalyType") or ""),
        str(record.get("resourceName") or record.get("entityName") or ""),
        reason[:80],
    )


def _dedupe_anomalies(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for record in records:
        key = _anomaly_key(record)
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique


def _render_anomalies(
    data: Any, *, anomaly_summary: dict[str, Any] | None
) -> list[str]:
    if not isinstance(data, dict):
        return ["  (unexpected response shape)", _preview_json(data)]
    records = [item for item in data.get("anomalies") or [] if isinstance(item, dict)]
    deduped = _dedupe_anomalies(records)
    meta = data.get("meta")
    if isinstance(meta, dict):
        counts = meta.get("counts")
        if isinstance(counts, dict):
            lines = [
                f"  listed: {len(records)}  "
                f"unique: {len(deduped)}  "
                f"total: {counts.get('total', '?')}  "
                f"remaining: {counts.get('remaining', '?')}",
            ]
        else:
            lines = [f"  listed: {len(records)}  unique: {len(deduped)}"]
    else:
        lines = [f"  listed: {len(records)}  unique: {len(deduped)}"]
    if anomaly_summary:
        expected = summary_new_count(anomaly_summary)
        if expected and len(records) != expected:
            lines.append(
                f"  warning: summary reports {expected} new anomalies; this list "
                "may include fabric-wide state rather than delta-only rows."
            )
    if not deduped:
        lines.append("  (no anomaly records returned)")
        return lines
    if len(records) != len(deduped):
        lines.append(f"  ({len(records) - len(deduped)} duplicate row(s) collapsed)")
    lines.append(
        "  severity     mnemonic                         resource              reason"
    )
    for record in deduped[:_ANOMALY_ROW_CAP]:
        severity = str(record.get("severity", ""))[:12]
        mnemonic = str(record.get("mnemonicTitle") or record.get("anomalyType") or "")[
            :32
        ]
        resource = str(record.get("resourceName") or record.get("entityName") or "")[
            :20
        ]
        reason = str(record.get("anomalyReason") or record.get("anomalyString") or "")
        reason = reason.replace("\n", " ")[:72]
        lines.append(f"  {severity:<12} {mnemonic:<32} {resource:<20} {reason}")
    if len(deduped) > _ANOMALY_ROW_CAP:
        lines.append(
            f"  ... {len(deduped) - _ANOMALY_ROW_CAP} more "
            "(use --output json for the full list)"
        )
    return lines


def _render_policy_diff(data: Any) -> list[str]:
    if data in (None, {}, []):
        return ["  (empty policy diff)"]
    if isinstance(data, dict):
        lines_data = data.get("lines")
        if isinstance(lines_data, list):
            changed = [
                line
                for line in lines_data
                if isinstance(line, dict) and line.get("changeType") != "unchanged"
            ]
            if not changed:
                return [
                    f"  {len(lines_data)} line(s) returned; none are added, "
                    "removed, or modified."
                ]
            lines = [f"  changed lines: {len(changed)} of {len(lines_data)}"]
            for entry in changed[:_POLICY_DIFF_CAP]:
                change = str(entry.get("changeType", ""))
                content = str(entry.get("lineContent", "")).replace("\n", " ")
                if len(content) > 100:
                    content = content[:97] + "..."
                lines.append(f"  [{change}] {content}")
            if len(changed) > _POLICY_DIFF_CAP:
                lines.append(
                    f"  ... {len(changed) - _POLICY_DIFF_CAP} more changed lines "
                    "(use --output json for the full diff)"
                )
            return lines
        lines = [f"  top-level keys: {', '.join(sorted(data))}"]
        lines.append(_preview_json(data, limit=800))
        return lines
    if isinstance(data, list):
        return [f"  list entries: {len(data)}", _preview_json(data, limit=800)]
    return [_preview_json(data, limit=800)]


def _preview_json(data: Any, limit: int = 400) -> str:
    text = json.dumps(data, indent=2, sort_keys=False)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
