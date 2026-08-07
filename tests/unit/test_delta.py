"""Delta analysis: status vocabulary and absence detection."""

from __future__ import annotations

import json

import pytest

from nac_nd.client import select_job
from nac_nd.exceptions import JobError
from tests.conftest import Lab, json_response

SUMMARY_PATH = "/api/v1/analyze/jobs/summary"
CREATE_PATH = "/api/v1/analyze/jobs/deltaAnalysis"


def entry(status: str, job_id: str = "job-1", **extra: object) -> dict:
    payload = {
        "jobId": job_id,
        "jobType": "EPOCH-DELTA-ANALYSIS",
        "fabricName": "FABRIC-A",
        "status": status,
    }
    payload.update(extra)
    return payload


def test_snapshot_ids_are_sent_as_the_epoch_uuid_fields(make_client) -> None:
    lab = Lab({CREATE_PATH: json_response({"jobId": "job-1"})})
    client = make_client(lab)

    job_id = client.create_delta_job(
        fabric="FABRIC-A", job_name="run-1", prior_id="snap-1", later_id="snap-2"
    )

    body = json.loads(lab.requests_to(CREATE_PATH)[0].content)
    assert job_id == "job-1"
    assert body["priorEpochUuid"] == "snap-1"
    assert body["laterEpochUuid"] == "snap-2"


def test_the_terminal_success_status_is_complete(make_client) -> None:
    """Delta status values are upper case and success is `COMPLETE`."""
    lab = Lab(
        {
            SUMMARY_PATH: [
                json_response({"entries": [entry("SCHEDULED")]}),
                json_response({"entries": [entry("COMPLETE")]}),
            ]
        }
    )
    client = make_client(lab)

    assert client.wait_delta_job("job-1")["status"] == "COMPLETE"


@pytest.mark.parametrize(
    "status", ["FAILED", "STOPPED", "ABORTED", "PARTIALLY_FAILED", "UNAVAILABLE"]
)
def test_every_unsuccessful_terminal_status_fails(make_client, status: str) -> None:
    lab = Lab({SUMMARY_PATH: json_response({"entries": [entry(status)]})})
    client = make_client(lab)

    with pytest.raises(JobError) as caught:
        client.wait_delta_job("job-1")

    assert caught.value.exit_code == 2
    assert status in str(caught.value)


def test_a_stopped_job_must_never_report_green(make_client) -> None:
    """A stopped job analysed nothing, so it fails rather than passes."""
    client = make_client(
        Lab({SUMMARY_PATH: json_response({"entries": [entry("STOPPED")]})})
    )

    with pytest.raises(JobError, match="cannot validate a change"):
        client.wait_delta_job("job-1")


def test_a_missing_job_is_an_empty_entries_array_not_a_404(make_client) -> None:
    """/jobs/summary returns HTTP 200 with `entries: []` for a missing job."""
    lab = Lab({SUMMARY_PATH: json_response({"entries": []})})
    # Production-like timings separate the grace window from the job timeout:
    # ~60s of absence is 6 polls, where the timeout would be 90.
    client = make_client(lab, poll_interval_seconds=10, job_timeout_minutes=15)

    with pytest.raises(JobError, match="200 with no entries"):
        client.wait_delta_job("job-1")

    assert len(lab.requests_to(SUMMARY_PATH)) < 10


def test_a_job_that_appears_late_is_tolerated(make_client) -> None:
    """A new job takes a poll or two to appear in the listing."""
    lab = Lab(
        {
            SUMMARY_PATH: [
                json_response({"entries": []}),
                json_response({"entries": [entry("RUNNING")]}),
                json_response({"entries": [entry("COMPLETE")]}),
            ]
        }
    )
    client = make_client(lab)

    assert client.wait_delta_job("job-1")["status"] == "COMPLETE"


def test_the_requested_job_is_picked_out_of_the_listing() -> None:
    """The server is asked to filter by job ID and the match is re-checked."""
    entries = [entry("COMPLETE", "other"), entry("RUNNING", "job-1")]

    assert select_job(entries, "job-1")["status"] == "RUNNING"
    assert select_job(entries, "absent") is None
    assert select_job([], "job-1") is None


def test_acknowledged_anomalies_are_excluded_server_side(make_client) -> None:
    path = "/api/v1/analyze/deltaAnalysis/summary"
    lab = Lab({path: json_response({"newAnomaliesCount": 0})})
    client = make_client(lab)

    client.delta_summary("job-1")
    client.delta_summary("job-1", include_acknowledged=True)

    sent = [
        request.url.params["includeAcknowledged"] for request in lab.requests_to(path)
    ]
    assert sent == ["false", "true"]
