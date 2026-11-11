"""delete-in-progress-job-requires-force."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-in-progress-job-requires-force"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    Raises AssertionError when the call succeeds.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

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

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteJob on a non-terminal job without force must fail; force=True must succeed."""
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-behav-thing-jobdel-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda _n=thing_name: iot.delete_thing(thingName=_n))
    thing_arn = iot.describe_thing(thingName=thing_name)["thingArn"]

    job_id = ctx.unique_name("sim2real-behav-job-forcedel-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=json.dumps({"operation": "noop"}),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _j=job_id: _delete_job(iot, _j))
    status = _eventually(
        lambda: iot.describe_job(jobId=job_id)["job"]["status"],
        lambda s: s in {"IN_PROGRESS", "QUEUED", "SCHEDULED"},
        timeout_s=20,
        interval_s=1.0,
    )

    code, message = _err(lambda: iot.delete_job(jobId=job_id))
    assert code == "InvalidStateTransitionException", f"expected InvalidStateTransitionException, got {code}"
    # The refusal names the status the job is in when DeleteJob sees it, which may have moved
    # on from the one the poll above read; it must still be one of the non-terminal statuses.
    refused_in = message.split(" in status ", 1)[-1].split(" ", 1)[0] if message else None
    assert refused_in in {"IN_PROGRESS", "QUEUED", "SCHEDULED"}, (
        f"DeleteJob refusal names status {refused_in!r} (poll read {status!r}): {message!r}"
    )
    expected = f"Job {job_id} in status {refused_in} cannot be deleted without force flag."
    assert message == expected, f"DeleteJob message {message!r} != {expected!r}"

    # the rejected delete must have no effect: an independent read shows the job
    # untouched and still in the same non-terminal state it was rejected in
    unaffected = iot.describe_job(jobId=job_id)["job"]
    assert unaffected["status"] in {"IN_PROGRESS", "QUEUED", "SCHEDULED"}, (
        f"job status is {unaffected['status']!r} after the rejected delete, "
        f"expected it unchanged in a non-terminal state"
    )

    iot.delete_job(jobId=job_id, force=True)

    # Force deletion is asynchronous: DescribeJob may briefly still resolve (often
    # reporting DELETION_IN_PROGRESS) before the job disappears entirely.
    _eventually(
        lambda: _err(lambda: iot.describe_job(jobId=job_id)),
        lambda e: e == ("ResourceNotFoundException", f"Job {job_id} cannot be found."),
        timeout_s=120,
        interval_s=3.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
