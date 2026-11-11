"""job-update-and-execution-listings."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-update-and-execution-listings"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

def _delete_job(iot, job_id):
    """Teardown: DeleteJob with force=True removes a job in any state, so no cancel is needed."""
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateJob mutates job metadata; job/thing execution listings and
    CancelJobExecution reflect the per-target execution state machine."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-jobupd-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-job-upd-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=json.dumps({"operation": "noop"}),
        description="initial description",
        tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda _n=job_id: _delete_job(iot, _n))

    iot.update_job(jobId=job_id, description="updated description")
    desc = _eventually(
        lambda: iot.describe_job(jobId=job_id)["job"],
        lambda j: j.get("description") == "updated description",
        timeout_s=30,
    )
    assert desc["description"] == "updated description", (
        f"expected description 'updated description', got {desc['description']!r}"
    )

    job_ids = [j["jobId"] for j in iot.list_jobs().get("jobs", [])]
    assert job_id in job_ids, f"{job_id} missing from ListJobs"

    execs = _eventually(
        lambda: iot.list_job_executions_for_job(jobId=job_id).get("executionSummaries", []),
        lambda e: len(e) >= 1,
        timeout_s=60,
    )
    assert any(e["thingArn"] == thing_arn for e in execs), execs

    for_thing = iot.list_job_executions_for_thing(thingName=thing).get("executionSummaries", [])
    assert any(e["jobId"] == job_id for e in for_thing), for_thing

    # Cancel just this thing's execution; force is required for a QUEUED execution.
    iot.cancel_job_execution(jobId=job_id, thingName=thing, force=True)
    status = _eventually(
        lambda: iot.describe_job_execution(jobId=job_id, thingName=thing)["execution"]["status"],
        lambda s: s == "CANCELED",
        timeout_s=60,
    )
    assert status == "CANCELED", status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
