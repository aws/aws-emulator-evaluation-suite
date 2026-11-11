"""associate-targets-job-limit-exceeded-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "associate-targets-job-limit-exceeded-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]

_TOTAL_TARGET_LIMIT = 100


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CONTINUOUS job accepts targets up to 100, and associating a 101st thing group
    fails with LimitExceededException "Target list exceeds size limit 100." and leaves
    the targets unchanged."""
    iot = ctx.client("iot")

    group_names = [
        ctx.unique_name(f"sim2real-atj-{i:03d}-") for i in range(_TOTAL_TARGET_LIMIT + 1)
    ]
    group_arns = _create_thing_groups_concurrently(ctx, iot, group_names)

    job_id = ctx.unique_name("sim2real-job-")
    iot.create_job(
        jobId=job_id,
        targets=[group_arns[0]],
        targetSelection="CONTINUOUS",
        document='{"operation": "noop"}',
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    # bring the total from 1 up to the documented max of 100 (99 more targets);
    # this batch succeeding is the positive control.
    iot.associate_targets_with_job(jobId=job_id, targets=group_arns[1:_TOTAL_TARGET_LIMIT])

    described = iot.describe_job(jobId=job_id)
    targets_at_limit = set(described["job"]["targets"])
    expected_at_limit = set(group_arns[:_TOTAL_TARGET_LIMIT])
    assert targets_at_limit == expected_at_limit, (
        f"expected exactly the {_TOTAL_TARGET_LIMIT} targets at the quota, "
        f"got {len(targets_at_limit)}: {targets_at_limit}"
    )

    err = _error(
        lambda: iot.associate_targets_with_job(
            jobId=job_id, targets=[group_arns[_TOTAL_TARGET_LIMIT]]
        )
    )
    assert err == ("LimitExceededException", f"Target list exceeds size limit {_TOTAL_TARGET_LIMIT}."), (
        f"expected LimitExceededException with the exact quota message, got {err!r}"
    )

    # effect absent: the rejected call must not have changed the job's target set at all
    described_after = iot.describe_job(jobId=job_id)
    job_targets_after = set(described_after["job"]["targets"])
    assert job_targets_after == expected_at_limit, (
        f"expected the target set to be unchanged by the rejected call, "
        f"expected {expected_at_limit}, got {job_targets_after}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_thing_groups_concurrently(ctx, iot, names: list) -> list:
    arns = [None] * len(names)

    def _make(i, name):
        resp = iot.create_thing_group(thingGroupName=name)
        ctx.on_cleanup(lambda n=name: iot.delete_thing_group(thingGroupName=n))
        return i, resp["thingGroupArn"]

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_make, i, name) for i, name in enumerate(names)]
        for fut in futures:
            i, arn = fut.result()
            arns[i] = arn
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
