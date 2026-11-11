"""job-lifecycle-cancel."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-lifecycle-cancel"
GROUP = 'job-lifecycle'
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
    """Teardown: DeleteJob with force=True removes a job in any state, so no cancel is needed."""
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Job state machine: create -> QUEUED/IN_PROGRESS -> cancel -> CANCELED; re-cancel must fail."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-job-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    job_id = ctx.unique_name("sim2real-behav-job-")
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=json.dumps({"operation": "noop"}),
    )
    ctx.on_cleanup(lambda _n=job_id: _delete_job(iot, _n))

    desc = _eventually(
        lambda: iot.describe_job(jobId=job_id),
        lambda d: d["job"]["status"] in ("QUEUED", "IN_PROGRESS"),
        timeout_s=60,
        interval_s=2,
    )
    assert desc["job"]["status"] in ("QUEUED", "IN_PROGRESS"), desc["job"]["status"]

    iot.cancel_job(jobId=job_id)
    canceled = _eventually(
        lambda: iot.describe_job(jobId=job_id),
        lambda d: d["job"]["status"] in ("CANCELED", "CANCELLED"),
        timeout_s=90,
        interval_s=3,
    )
    assert canceled["job"]["status"] in ("CANCELED", "CANCELLED"), canceled["job"]["status"]

    # Re-cancel a job already in a terminal CANCELED state: this is a one-directional
    # transition, so there is no restore leg (the job can never become cancelable again).
    code, message = _err(lambda: iot.cancel_job(jobId=job_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = f"Job {job_id} in status {canceled['job']['status']} cannot be canceled."
    assert message == expected, f"CancelJob message {message!r} != {expected!r}"

    unaffected = iot.describe_job(jobId=job_id)
    assert unaffected["job"]["status"] in ("CANCELED", "CANCELLED"), (
        f"expected status to remain CANCELED after the rejected re-cancel, got {unaffected['job']['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
