"""create-job-nonexistent-target-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-job-nonexistent-target-fails"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.

    Raises on unexpected success, so accepting the bogus target fails clearly
    as an acceptance.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

def _delete_job(iot, job_id):
    """Teardown: cancel then force-delete a job; only a missing or already-terminal job is tolerated."""
    try:
        iot.cancel_job(jobId=job_id, force=True, comment="cleanup")
    except ClientError as exc:
        # An already-terminal job needs no cancel; the delete below still runs.
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidStateTransitionException"):
            raise
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates job writes asynchronously, so the first few reads
    can raise before the job status settles.
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateJob targeting a well-formed, same-account thing ARN that does not exist
    must fail with ResourceNotFoundException (not AccessDenied); once the target is
    created, the identical call must succeed."""
    iot = ctx.client("iot")
    # Must be the caller's own account -- a foreign account id yields AccessDeniedException,
    # which would mask the referential-integrity behavior under test.
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: CreateJob against a real target succeeds, so the negative
    # below cannot be indistinguishable from "this target rejects every CreateJob".
    control_thing = ctx.unique_name("sim2real-behav-thing-badtarget-control-")
    iot.create_thing(thingName=control_thing)
    ctx.on_cleanup(lambda _n=control_thing: iot.delete_thing(thingName=_n))
    control_thing_arn = iot.describe_thing(thingName=control_thing)["thingArn"]
    control_job_id = ctx.unique_name("sim2real-behav-job-badtarget-control-")
    iot.create_job(
        jobId=control_job_id,
        targets=[control_thing_arn],
        document=json.dumps({"operation": "noop"}),
    )
    ctx.on_cleanup(lambda _n=control_job_id: _delete_job(iot, _n))
    _eventually(
        lambda: iot.describe_job(jobId=control_job_id)["job"]["status"],
        lambda s: s in ("QUEUED", "IN_PROGRESS"),
    )

    # Break: target the ARN of a thing that does not exist yet.
    missing_thing = ctx.unique_name("no-such-thing-")
    bogus_arn = f"arn:aws:iot:{ctx.region}:{account}:thing/{missing_thing}"
    job_id = ctx.unique_name("sim2real-behav-job-badtarget-")

    code, message = _err(
        lambda: iot.create_job(
            jobId=job_id, targets=[bogus_arn], document=json.dumps({"operation": "noop"})
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Thing {missing_thing} cannot be found."
    assert message == expected, f"CreateJob message {message!r} != {expected!r}"

    code2, message2 = _err(lambda: iot.describe_job(jobId=job_id))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected2 = f"Job {job_id} cannot be found."
    assert message2 == expected2, f"DescribeJob message {message2!r} != {expected2!r}"

    # Restore: create the target, then retry the identical call -- it must now succeed.
    iot.create_thing(thingName=missing_thing)
    ctx.on_cleanup(lambda _n=missing_thing: iot.delete_thing(thingName=_n))
    iot.create_job(
        jobId=job_id, targets=[bogus_arn], document=json.dumps({"operation": "noop"})
    )
    ctx.on_cleanup(lambda _n=job_id: _delete_job(iot, _n))
    _eventually(
        lambda: iot.describe_job(jobId=job_id)["job"]["status"],
        lambda s: s in ("QUEUED", "IN_PROGRESS"),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
