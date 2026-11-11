"""job-targets-limit-exceeded-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-targets-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise on success."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateTargetsWithJob rejects pushing a CONTINUOUS IN_PROGRESS job past 100 targets with
    LimitExceededException, leaving the job's targets unchanged rather than truncating the list.
    """
    iot = ctx.client("iot")

    job_group_name = ctx.unique_name("sim2real-jobtarget0-")
    iot.create_thing_group(thingGroupName=job_group_name)
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=job_group_name))
    job_target_arn = iot.describe_thing_group(thingGroupName=job_group_name)["thingGroupArn"]

    job_id = ctx.unique_name("sim2real-jobtargets-")
    iot.create_job(
        jobId=job_id,
        targets=[job_target_arn],
        document='{"op":"noop"}',
        targetSelection="CONTINUOUS",
    )
    ctx.on_cleanup(lambda: _safe_delete_job(iot, job_id))

    # AssociateTargetsWithJob requires the job to currently be IN_PROGRESS.
    status = _poll_until(
        lambda: iot.describe_job(jobId=job_id)["job"]["status"],
        lambda s: s == "IN_PROGRESS",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status == "IN_PROGRESS", f"job never reached IN_PROGRESS, last status={status}"

    # 100 more groups push the job to 101 targets, one over the quota.
    extra_names = [ctx.unique_name(f"sim2real-jobtarget-{i}-") for i in range(100)]

    def _create_group(n):
        iot.create_thing_group(thingGroupName=n)
        return iot.describe_thing_group(thingGroupName=n)["thingGroupArn"]

    with ThreadPoolExecutor(max_workers=20) as pool:
        extra_arns = list(pool.map(_create_group, extra_names))
    for n in extra_names:
        ctx.on_cleanup(lambda n=n: iot.delete_thing_group(thingGroupName=n))

    code, message = _error_code(lambda: iot.associate_targets_with_job(jobId=job_id, targets=extra_arns))
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code}"
    expected = "Target list exceeds size limit 100."
    assert message == expected, f"AssociateTargetsWithJob message {message!r} != {expected!r}"

    targets_after_reject = iot.describe_job(jobId=job_id)["job"]["targets"]
    assert targets_after_reject == [job_target_arn], (
        f"expected targets unchanged at [{job_target_arn}], got {targets_after_reject}"
    )

    # Positive control: adding a single target within the quota succeeds.
    control_name = ctx.unique_name("sim2real-jobtarget-control-")
    iot.create_thing_group(thingGroupName=control_name)
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=control_name))
    control_arn = iot.describe_thing_group(thingGroupName=control_name)["thingGroupArn"]

    iot.associate_targets_with_job(jobId=job_id, targets=[control_arn])
    targets_after_control = iot.describe_job(jobId=job_id)["job"]["targets"]
    assert set(targets_after_control) == {job_target_arn, control_arn}, (
        f"expected targets {{{job_target_arn}, {control_arn}}}, got {set(targets_after_control)}"
    )


def _safe_delete_job(iot, job_id: str) -> None:
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
