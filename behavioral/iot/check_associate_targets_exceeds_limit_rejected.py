"""associate-targets-exceeds-limit-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "associate-targets-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]

# AWS IoT Jobs quota "Job Targets" (L-9D1E0A0D) is fixed at 100 and is not adjustable.
_JOB_TARGET_LIMIT = 100


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateTargetsWithJob succeeds up to 100 targets, and the call that would
    exceed it fails with LimitExceededException "Target list exceeds size limit 100."
    and leaves the target list unchanged."""
    iot = ctx.client("iot")

    group_arns = _create_thing_groups(ctx, iot, _JOB_TARGET_LIMIT + 1)
    job_id = ctx.unique_name("sim2real-jobtargets-")
    # AssociateTargetsWithJob only accepts a CONTINUOUS job that is still IN_PROGRESS, and
    # only thing-GROUP ARNs (not individual thing ARNs) as targets -- a default SNAPSHOT
    # job, or a target that isn't a thing-group ARN, is rejected with InvalidRequestException.
    iot.create_job(
        jobId=job_id,
        targets=group_arns[: _JOB_TARGET_LIMIT - 1],
        document='{"op":"noop"}',
        targetSelection="CONTINUOUS",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    # positive control: associating the last remaining slot (target #100) succeeds
    iot.associate_targets_with_job(jobId=job_id, targets=[group_arns[_JOB_TARGET_LIMIT - 1]])
    job_at_limit = iot.describe_job(jobId=job_id)["job"]
    assert len(job_at_limit["targets"]) == _JOB_TARGET_LIMIT, (
        f"expected {_JOB_TARGET_LIMIT} targets at the quota boundary, "
        f"got {len(job_at_limit['targets'])}"
    )

    # negative: one more target would push the job over the 100-target quota
    over_limit_target = group_arns[_JOB_TARGET_LIMIT]
    err = _error(lambda: iot.associate_targets_with_job(
        jobId=job_id, targets=[over_limit_target]))
    assert err == ("LimitExceededException", f"Target list exceeds size limit {_JOB_TARGET_LIMIT}."), (
        f"expected LimitExceededException with the exact quota message, got {err!r}"
    )

    # effect absent: the job's target list did not grow past the quota
    job_after = iot.describe_job(jobId=job_id)["job"]
    assert len(job_after["targets"]) == _JOB_TARGET_LIMIT, (
        f"expected {_JOB_TARGET_LIMIT} targets after the rejected call, "
        f"got {len(job_after['targets'])}"
    )
    assert over_limit_target not in job_after["targets"], (
        f"rejected target {over_limit_target!r} must not appear in {job_after['targets']!r}"
    )
    # and stronger still: the list is byte-for-byte unchanged, not just the right length
    assert job_after["targets"] == job_at_limit["targets"], (
        f"rejected call must leave targets unchanged: before={job_at_limit['targets']!r} "
        f"after={job_after['targets']!r}"
    )


def _create_thing_groups(ctx, iot, count):
    names = [ctx.unique_name(f"sim2real-jtg{i}-") for i in range(count)]

    def _make(name):
        resp = iot.create_thing_group(
            thingGroupName=name, tags=[{"Key": "sim2real", "Value": CHECK}]
        )
        return name, resp["thingGroupArn"]

    with ThreadPoolExecutor(max_workers=20) as pool:
        pairs = list(pool.map(_make, names))

    for name, _arn in pairs:
        ctx.on_cleanup(lambda n=name: iot.delete_thing_group(thingGroupName=n))

    return [arn for _, arn in pairs]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
