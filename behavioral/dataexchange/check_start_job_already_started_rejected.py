"""start-job-already-started-rejected."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-job-already-started-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A new import job starts WAITING and leaves it on the first StartJob; once terminal, a second StartJob
    fails with ConflictException and its exact message and the terminal state is unchanged."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    md5_b64 = base64.b64encode(hashlib.md5(b"sim2real-unused-body").digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": "sim2real-double-start.txt",
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    assert job["State"] == "WAITING", f"expected freshly created job to be WAITING, got {job['State']!r}"

    dx.start_job(JobId=job_id)  # positive control: the legitimate first start succeeds
    state_after_first = dx.get_job(JobId=job_id)["State"]
    assert state_after_first != "WAITING", (
        f"expected StartJob to move the job off WAITING, still {state_after_first!r}"
    )

    # No bytes were ever uploaded to the signed URL, so the job settles into a terminal
    # error state on its own; wait for that so the state is stable before re-probing.
    terminal_state = _poll_job_state(dx, job_id, {"COMPLETED", "ERROR", "TIMED_OUT"}, timeout_s=90)

    code, message = _error(lambda: dx.start_job(JobId=job_id))
    assert code == "ConflictException", f"expected ConflictException restarting a {terminal_state} job, got {code!r}"
    assert message == "Cannot start the requested Job. To start a Job, it must be in the WAITING state.", f"expected the exact refusal message, got {message!r}"

    state_after_second_attempt = dx.get_job(JobId=job_id)["State"]
    assert state_after_second_attempt == terminal_state, (
        f"expected rejected restart to leave state at {terminal_state!r}, got {state_after_second_attempt!r}"
    )


def _poll_job_state(dx, job_id: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states and time.monotonic() < deadline:
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    if state not in target_states:
        raise AssertionError(
            f"job {job_id} did not reach {target_states} within {timeout_s}s; last saw {state!r}"
        )
    return state


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(
        DataSetId=dataset_id,
        Comment="sim2real revision",
        Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"},
    )
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
