"""delete-job-execution-removes-single-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-job-execution-removes-single-execution"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _try(fn):
    """Call fn, returning its result, or None if it raised; used to wait out eventual consistency."""
    try:
        return fn()
    except Exception:
        return None

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
    """Teardown: cancel then force-delete a job; only a missing or already-terminal job is tolerated."""
    try:
        iot.cancel_job(jobId=job_id, force=True)
    except ClientError as exc:
        # An already-terminal job needs no cancel; the delete below still runs.
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidStateTransitionException"):
            raise
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteJobExecution removes exactly one thing's execution record from a job,
    leaving a sibling thing's execution on the same job untouched."""
    iot = ctx.client("iot")
    doomed = ctx.unique_name("sim2real-behav-thing-execdel-")
    survivor = ctx.unique_name("sim2real-behav-thing-execdel-keep-")
    iot.create_thing(thingName=doomed)
    ctx.on_cleanup(lambda _n=doomed: iot.delete_thing(thingName=_n))
    iot.create_thing(thingName=survivor)
    ctx.on_cleanup(lambda _n=survivor: iot.delete_thing(thingName=_n))
    doomed_arn = iot.describe_thing(thingName=doomed)["thingArn"]
    survivor_arn = iot.describe_thing(thingName=survivor)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-job-execdel-")
    iot.create_job(
        jobId=job_id,
        targets=[doomed_arn, survivor_arn],
        document=json.dumps({"operation": "noop"}),
    )
    ctx.on_cleanup(lambda _j=job_id: _delete_job(iot, _j))

    doomed_execution = _eventually(
        lambda: _try(lambda: iot.describe_job_execution(jobId=job_id, thingName=doomed)),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2.0,
    )["execution"]
    execution_number = doomed_execution["executionNumber"]

    survivor_execution = _eventually(
        lambda: _try(lambda: iot.describe_job_execution(jobId=job_id, thingName=survivor)),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2.0,
    )["execution"]
    survivor_execution_number = survivor_execution["executionNumber"]

    iot.delete_job_execution(
        jobId=job_id, thingName=doomed, executionNumber=execution_number, force=True
    )

    _eventually(
        lambda: _err(
            lambda: iot.describe_job_execution(jobId=job_id, thingName=doomed)
        )[0],
        lambda c: c == "ResourceNotFoundException",
        timeout_s=60,
        interval_s=2.0,
    )

    # A second delete of the same, now-gone execution must fail the same way —
    # the removal is not just absent from a stale read, the id is dead.
    redelete_code, redelete_message = _err(
        lambda: iot.delete_job_execution(
            jobId=job_id, thingName=doomed, executionNumber=execution_number, force=True
        )
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting a gone execution, got {redelete_code!r}"
    )
    expected_message = f"Job execution for thing {doomed} cannot be found within job {job_id}."
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )

    # The sibling thing's execution on the SAME job must be untouched — this is
    # the "single" in the check's name: deleting one thing's execution must not
    # reach the other thing's execution on the same job.
    still_there = iot.describe_job_execution(jobId=job_id, thingName=survivor)["execution"]
    assert still_there["executionNumber"] == survivor_execution_number, (
        f"survivor execution number changed: "
        f"{survivor_execution_number!r} -> {still_there['executionNumber']!r}"
    )
    assert still_there["status"] == survivor_execution["status"], (
        f"survivor execution status changed: "
        f"{survivor_execution['status']!r} -> {still_there['status']!r}"
    )

    # The parent job itself must survive deletion of one execution.
    job_after = iot.describe_job(jobId=job_id)["job"]
    assert job_after["jobId"] == job_id, (
        f"parent job disappeared after deleting one execution: {job_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
