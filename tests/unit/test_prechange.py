"""Pre-change analysis and the verdict gate."""

from __future__ import annotations

import json

import pytest

from nac_nd.client import prechange_delta_job_id
from nac_nd.exceptions import ApiError, InputError, JobError
from nac_nd.report import DEFAULT_FAIL_ON, build_verdict
from tests.conftest import Lab, json_response

JOB_PATH = "/api/v1/analyze/jobs/prechangeAnalysis/abc123"
CREATE_PATH = "/api/v1/analyze/jobs/prechangeAnalysis/file"
REMOVE_PATH = "/api/v1/analyze/jobs/deltaAnalysis/actions/remove"
JOBS_SUMMARY_PATH = "/api/v1/analyze/jobs/summary"

BASE_SNAPSHOT = {
    "snapshotId": "snap-1",
    "collectionTimestamp": "2026-08-07T10:38:56Z",
    "analysisTimestamp": "2026-08-07T10:39:54Z",
}

# What /deltaAnalysis/summary returns while an analysis is still running: a
# well-formed, all-zero result.
MID_RUN_SUMMARY = {
    "newAnomaliesCount": 0,
    "clearedAnomaliesCount": 0,
    "unchangedAnomaliesCount": 0,
    "earlierSnapshotAnomaliesCount": 0,
    "laterSnapshotAnomaliesCount": 0,
    "anomalyCountBySeverity": [
        {
            "severity": severity,
            "newCount": 0,
            "clearedCount": 0,
            "unchangedCount": 0,
            "earlierCount": 0,
            "laterCount": 0,
        }
        for severity in ("critical", "major", "minor", "warning", "info", "unknown")
    ],
}


def job(status: str, **extra: object) -> dict:
    payload = {
        "jobId": "abc123",
        "fabricName": "FABRIC-A",
        "analysisStatus": status,
        "analysisScheduleId": "sched-1",
        "baseSnapshotId": "snap-1",
    }
    payload.update(extra)
    return payload


# -- the gate --------------------------------------------------------------


@pytest.mark.parametrize("status", ["submitted", "running", "saved", ""])
def test_an_unfinished_analysis_never_yields_a_delta_job_id(status: str) -> None:
    """The delta job ID is withheld until the analysis status is `completed`."""
    with pytest.raises(JobError, match="all-zero"):
        prechange_delta_job_id(job(status, spanshotDeltaJobId="EPOCH-DELTA-x"))


def test_a_mid_run_summary_would_otherwise_read_as_a_clean_pass() -> None:
    """A mid-run summary produces a passing verdict, so status gates it."""
    verdict = build_verdict(MID_RUN_SUMMARY, DEFAULT_FAIL_ON)

    assert verdict.passed is True
    assert verdict.total_new == 0


def test_the_delta_job_id_field_name_is_misspelled_on_the_wire() -> None:
    """The API spells the field `spanshotDeltaJobId`."""
    completed = job("completed", spanshotDeltaJobId="EPOCH-DELTA-ANALYSIS-uuid")

    assert prechange_delta_job_id(completed) == "EPOCH-DELTA-ANALYSIS-uuid"

    with pytest.raises(JobError, match="no spanshotDeltaJobId"):
        prechange_delta_job_id(job("completed", snapshotDeltaJobId="EPOCH-DELTA-x"))


def test_the_status_comparison_is_case_insensitive() -> None:
    """Pre-change status values are lower case; delta values are upper case."""
    completed = job("COMPLETED", spanshotDeltaJobId="d1")

    assert prechange_delta_job_id(completed) == "d1"


# -- create ----------------------------------------------------------------


def create_client(make_client, response) -> tuple:
    lab = Lab({CREATE_PATH: response})
    return make_client(lab), lab


def test_the_create_response_is_wrapped_in_data(make_client) -> None:
    """Create wraps the job in `data`; the single-job GET does not."""
    client, _ = create_client(
        make_client,
        json_response({"data": {"jobId": "abc123", "analysisStatus": "submitted"}}),
    )

    created = client.create_prechange_analysis(
        fabric="FABRIC-A",
        name="run-1",
        base_snapshot=BASE_SNAPSHOT,
        file_name="config.json",
        content=b"{}",
    )

    assert created["jobId"] == "abc123"


def test_the_single_job_get_is_bare(make_client) -> None:
    """`GET /jobs/prechangeAnalysis/{jobId}` returns the job with no wrapper."""
    client = make_client(Lab({JOB_PATH: json_response(job("completed"))}))

    assert client.get_prechange_analysis("abc123")["analysisStatus"] == "completed"


def test_object_collection_is_sent_as_an_empty_json_array(make_client) -> None:
    """`objectCollection` must be a JSON array; an object returns HTTP 500."""
    client, lab = create_client(
        make_client, json_response({"data": {"jobId": "abc123"}})
    )

    client.create_prechange_analysis(
        fabric="FABRIC-A",
        name="run-1",
        base_snapshot=BASE_SNAPSHOT,
        file_name="config.json",
        content=b'{"imdata": []}',
    )

    request = lab.requests_to(CREATE_PATH)[0]
    body = request.content.decode()
    raw = body.split('name="data"\r\n\r\n', 1)[1].split("\r\n--", 1)[0]
    data_part = json.loads(raw)
    assert data_part["objectCollection"] == []
    assert isinstance(data_part["objectCollection"], list)
    assert data_part["baseSnapshotId"] == "snap-1"
    assert data_part["baseSnapshotCollectionDate"] == "2026-08-07T10:38:56Z"
    assert request.url.params["fabricName"] == "FABRIC-A"


def test_a_rejected_configuration_reports_the_code_and_message(make_client) -> None:
    """A validation error names the offending object and exits 4."""
    client, _ = create_client(
        make_client,
        json_response(
            {
                "code": 4011,
                "message": "Status created not valid for object of type fvRsCtx",
            },
            400,
        ),
    )

    with pytest.raises(InputError) as caught:
        client.create_prechange_analysis(
            fabric="FABRIC-A",
            name="run-1",
            base_snapshot=BASE_SNAPSHOT,
            file_name="config.json",
            content=b"{}",
        )

    assert caught.value.exit_code == 4
    assert "4011" in str(caught.value)
    assert "fvRsCtx" in str(caught.value)


def test_other_create_failures_stay_generic(make_client) -> None:
    client, _ = create_client(make_client, json_response({"message": "boom"}, 500))

    with pytest.raises(ApiError):
        client.create_prechange_analysis(
            fabric="FABRIC-A",
            name="run-1",
            base_snapshot=BASE_SNAPSHOT,
            file_name="config.json",
            content=b"{}",
        )


# -- polling ---------------------------------------------------------------


def test_polling_follows_the_lower_case_status_vocabulary(make_client) -> None:
    lab = Lab(
        {
            JOB_PATH: [
                json_response(job("submitted")),
                json_response(job("running")),
                json_response(job("completed", spanshotDeltaJobId="d1")),
            ]
        }
    )
    client = make_client(lab)

    finished = client.wait_prechange_analysis("abc123")

    assert finished["analysisStatus"] == "completed"
    assert len(lab.requests_to(JOB_PATH)) == 3


def test_a_stopped_analysis_is_a_failure(make_client) -> None:
    """A stopped analysis examined nothing, so it fails rather than passes."""
    client = make_client(Lab({JOB_PATH: json_response(job("stopped"))}))

    with pytest.raises(JobError) as caught:
        client.wait_prechange_analysis("abc123")

    assert caught.value.exit_code == 2
    assert "cannot vouch" in str(caught.value)


def test_a_failed_analysis_surfaces_its_error_message(make_client) -> None:
    client = make_client(
        Lab({JOB_PATH: json_response(job("failed", errorMessage="parse error"))})
    )

    with pytest.raises(JobError, match="parse error"):
        client.wait_prechange_analysis("abc123")


def test_a_saved_draft_is_not_waited_on(make_client) -> None:
    """`saved` is a draft that never progresses, so it is not polled."""
    lab = Lab({JOB_PATH: json_response(job("saved"))})
    client = make_client(lab)

    with pytest.raises(JobError, match="saved draft"):
        client.wait_prechange_analysis("abc123")

    assert len(lab.requests_to(JOB_PATH)) == 1


def test_a_vanished_job_fails_immediately(make_client) -> None:
    """A job that no longer exists fails without further polling."""
    lab = Lab({JOB_PATH: json_response({"message": "job abc123 not found"}, 400)})
    client = make_client(lab)

    with pytest.raises(JobError, match="no longer exists"):
        client.wait_prechange_analysis("abc123")

    assert len(lab.requests_to(JOB_PATH)) == 1


# -- cleanup ---------------------------------------------------------------


def test_cleanup_removes_every_child_delta_job(make_client) -> None:
    """Children are found by matching `configName` to `analysisScheduleId`."""
    summary_entries = [
        json_response(
            {
                "entries": [
                    {"jobId": "d1", "configName": "sched-1"},
                    {"jobId": "d2", "configName": "sched-1"},
                    {"jobId": "d9", "configName": "other-schedule"},
                ]
            }
        ),
        json_response({"entries": []}),
    ]
    lab = Lab(
        {
            JOBS_SUMMARY_PATH: summary_entries,
            REMOVE_PATH: json_response({}),
            JOB_PATH: json_response({}),
        }
    )
    client = make_client(lab)

    leftover = client.cleanup_prechange("FABRIC-A", job("completed"))

    assert leftover == []
    removal = lab.requests_to(REMOVE_PATH)[0]
    assert json.loads(removal.content)["jobIdCollection"] == ["d1", "d2"]


def test_cleanup_reports_children_that_survive(make_client) -> None:
    """Removal is asynchronous, so absence is re-checked afterwards."""
    entry = {"jobId": "d1", "configName": "sched-1"}
    lab = Lab(
        {
            JOBS_SUMMARY_PATH: json_response({"entries": [entry]}),
            REMOVE_PATH: json_response({}),
            JOB_PATH: json_response({}),
        }
    )
    client = make_client(lab)

    assert client.cleanup_prechange("FABRIC-A", job("completed")) == ["d1"]
