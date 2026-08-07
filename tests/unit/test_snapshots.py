"""Snapshot listing, ordering and selection."""

from __future__ import annotations

import logging

import pytest

from nac_nd.client import (
    SNAPSHOT_RECORD_CAP,
    finished_snapshots,
    resolve_snapshot_ids,
    select_snapshot,
    sort_snapshots,
)
from nac_nd.exceptions import InputError, JobError
from tests.conftest import Lab, json_response


def snapshot(snapshot_id: str, collected: str, status: str = "finished") -> dict:
    return {
        "snapshotId": snapshot_id,
        "analysisJobId": f"job-{snapshot_id}",
        "collectionTimestamp": collected,
        "analysisTimestamp": collected.replace(":00Z", ":58Z"),
        "snapshotType": "online",
        "status": status,
        "fabricName": "FABRIC-A",
    }


NEWEST = snapshot("s3", "2026-08-07T12:00:00Z")
MIDDLE = snapshot("s2", "2026-08-07T11:00:00Z")
OLDEST = snapshot("s1", "2026-08-07T10:00:00Z")


def test_snapshots_are_sorted_client_side() -> None:
    """The API does not guarantee an order, so sorting happens client-side."""
    ordered = sort_snapshots([MIDDLE, OLDEST, NEWEST])

    assert [record["snapshotId"] for record in ordered] == ["s3", "s2", "s1"]


def test_status_is_compared_case_insensitively() -> None:
    """`status` is returned lower case, so the comparison is case-insensitive."""
    records = [
        snapshot("a", "2026-08-07T10:00:00Z", status="FINISHED"),
        snapshot("b", "2026-08-07T11:00:00Z", status="finished"),
        snapshot("c", "2026-08-07T12:00:00Z", status="inProgress"),
    ]

    kept = {record["snapshotId"] for record in finished_snapshots(records)}

    assert kept == {"a", "b"}


def test_latest_selectors_walk_backwards_from_the_newest() -> None:
    available = [OLDEST, NEWEST, MIDDLE]

    assert select_snapshot(available, "latest")["snapshotId"] == "s3"
    assert select_snapshot(available, "latest-1")["snapshotId"] == "s2"
    assert select_snapshot(available, "latest-2")["snapshotId"] == "s1"
    assert select_snapshot(available, "s2")["snapshotId"] == "s2"


def test_an_out_of_range_offset_says_how_many_exist() -> None:
    with pytest.raises(InputError, match="only 3 finished snapshot"):
        select_snapshot([OLDEST, MIDDLE, NEWEST], "latest-9")


def test_an_unknown_snapshot_id_is_bad_input() -> None:
    with pytest.raises(InputError) as caught:
        select_snapshot([NEWEST], "not-a-snapshot")

    assert caught.value.exit_code == 4


def test_each_snapshot_type_is_requested_explicitly(make_client) -> None:
    """Omitting `snapshotType` returns `online` only, not every type."""
    lab = Lab({"/api/v1/analyze/fabricSnapshots": json_response({"snapshots": []})})
    client = make_client(lab)

    client.list_snapshots("FABRIC-A", snapshot_types=("online", "prechange"))

    asked = [
        request.url.params["snapshotType"]
        for request in lab.requests_to("/api/v1/analyze/fabricSnapshots")
    ]
    assert asked == ["online", "prechange"]


def test_the_fifty_record_cap_is_reported(make_client, caplog) -> None:
    """The endpoint caps at 50 records, so unreachable ones are warned about."""
    records = [
        snapshot(f"s{index}", f"2026-08-07T{index:02d}:00:00Z")
        for index in range(SNAPSHOT_RECORD_CAP)
    ]
    body = {
        "snapshots": records,
        "meta": {"counts": {"total": 91, "remaining": 41}},
    }
    lab = Lab({"/api/v1/analyze/fabricSnapshots": json_response(body)})
    client = make_client(lab)

    with caplog.at_level(logging.WARNING):
        client.list_snapshots("FABRIC-A")

    assert "41 more" in caplog.text
    assert "--since" in caplog.text


def test_the_date_window_is_passed_through(make_client) -> None:
    lab = Lab({"/api/v1/analyze/fabricSnapshots": json_response({"snapshots": []})})
    client = make_client(lab)

    client.list_snapshots(
        "FABRIC-A", start_date="2026-08-01T00:00:00Z", end_date="2026-08-02T00:00:00Z"
    )

    params = lab.requests_to("/api/v1/analyze/fabricSnapshots")[0].url.params
    assert params["startDate"] == "2026-08-01T00:00:00Z"
    assert params["endDate"] == "2026-08-02T00:00:00Z"


def test_a_fabric_with_no_finished_snapshots_is_a_job_error(make_client) -> None:
    unfinished = snapshot("s1", "2026-08-07T10:00:00Z", "inProgress")
    lab = Lab(
        {"/api/v1/analyze/fabricSnapshots": json_response({"snapshots": [unfinished]})}
    )
    client = make_client(lab)

    with pytest.raises(JobError, match="no finished snapshots"):
        client.resolve_snapshot("FABRIC-A", "latest")


def test_delta_identifiers_come_from_snapshot_id() -> None:
    """`priorEpochUuid` and `laterEpochUuid` take `snapshotId` verbatim."""
    prior, later = resolve_snapshot_ids(OLDEST, NEWEST)

    assert (prior, later) == ("s1", "s3")


def test_comparing_a_snapshot_with_itself_is_refused() -> None:
    with pytest.raises(InputError, match="nothing to compare"):
        resolve_snapshot_ids(NEWEST, NEWEST)
