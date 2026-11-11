"""jq-create-with-unknown-scheduling-policy-fails."""

from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "jq-create-with-unknown-scheduling-policy-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(); return on a "does not exist" refusal and raise every other error."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting input
    AWS refuses fails as itself and not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected this CreateJobQueue call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_se(bat, name):
    envs = bat.describe_service_environments(serviceEnvironments=[name]).get(
        "serviceEnvironments", []
    )
    return envs[0] if envs else None


def _teardown_se(ctx, bat, name):
    """Disable a service environment, then delete it; an already-gone one is fine."""
    _swallow(lambda: bat.update_service_environment(serviceEnvironment=name, state="DISABLED"))
    _retry_delete(lambda: bat.delete_service_environment(serviceEnvironment=name))


def _create_service_environment(ctx, bat, max_capacity=4):
    name = ctx.unique_name("sim2real-behav-se-")
    resp = bat.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        state="ENABLED",
        capacityLimits=[{"maxCapacity": max_capacity, "capacityUnit": "NUM_INSTANCES"}],
    )
    ctx.on_cleanup(lambda: _teardown_se(ctx, bat, name))
    se = _poll_until(
        lambda: _describe_se(bat, name),
        lambda se: se is not None and se.get("status") in ("VALID", "INVALID"),
        timeout_s=120,
        interval_s=3,
        description=f"service environment {name} settled",
    )
    assert se["status"] == "VALID", f"prerequisite service environment failed to settle: {se}"
    return name, resp["serviceEnvironmentArn"]


def _create_scheduling_policy(ctx, bat, name):
    resp = bat.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: bat.delete_scheduling_policy(arn=resp["arn"])))
    return resp["arn"]


def _teardown_jq(bat, name):
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _retry_delete(lambda: bat.delete_job_queue(jobQueue=name))
    _wait_jq_gone(bat, name)


def _create_job_queue(ctx, bat, name, se_arn, scheduling_policy_arn):
    bat.create_job_queue(
        jobQueueName=name,
        jobQueueType="SAGEMAKER_TRAINING",
        state="ENABLED",
        priority=1,
        serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
        schedulingPolicyArn=scheduling_policy_arn,
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, name))
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") == "VALID",
        timeout_s=90,
        interval_s=2,
        description=f"job queue {name} VALID",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateJobQueue naming a scheduling policy ARN that does not exist fails with ClientException
    and the exact message and leaves no queue, while the identical call succeeds once that policy
    exists: the rejection is about the missing policy alone."""
    bat = ctx.client("batch")
    _se_name, se_arn = _create_service_environment(ctx, bat)

    # positive control: a real scheduling policy makes an otherwise-identical CreateJobQueue succeed.
    control_sp_arn = _create_scheduling_policy(ctx, bat, ctx.unique_name("sim2real-behav-sp-ctl-"))
    control_jq = _create_job_queue(
        ctx, bat, ctx.unique_name("sim2real-behav-sjq-ctl-"), se_arn, control_sp_arn
    )
    assert control_jq["schedulingPolicyArn"] == control_sp_arn, (
        f"positive control queue should reference the real policy, "
        f"got {control_jq.get('schedulingPolicyArn')!r} != {control_sp_arn!r}"
    )

    # break exactly one thing: reference a scheduling policy that does not exist yet.
    account = ctx.client("sts").get_caller_identity()["Account"]
    target_name = ctx.unique_name("sim2real-behav-sp-absent-")
    target_arn = f"arn:aws:batch:{ctx.region}:{account}:scheduling-policy/{target_name}"
    jq_name = ctx.unique_name("sim2real-behav-sjq-")

    def _attempt():
        return bat.create_job_queue(
            jobQueueName=jq_name,
            jobQueueType="SAGEMAKER_TRAINING",
            state="ENABLED",
            priority=1,
            serviceEnvironmentOrder=[{"order": 1, "serviceEnvironment": se_arn}],
            schedulingPolicyArn=target_arn,
        )

    error = _client_error(_attempt)
    assert error.get("Code") == "ClientException", (
        f"expected ClientException for an unknown scheduling policy reference, "
        f"got {error.get('Code')!r}: {error.get('Message')!r}"
    )
    expected_message = f"SchedulingPolicy {target_arn} not found."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    assert _describe_jq(bat, jq_name) is None, "rejected CreateJobQueue must not leave a queue behind"

    # restore: create the scheduling policy the request named, then retry the identical call.
    restored_arn = _create_scheduling_policy(ctx, bat, target_name)
    assert restored_arn == target_arn, (
        f"restored policy arn {restored_arn!r} does not match the originally-referenced "
        f"{target_arn!r}; the retry below would not be the identical call"
    )
    restored_jq = _create_job_queue(ctx, bat, jq_name, se_arn, target_arn)
    assert restored_jq["schedulingPolicyArn"] == target_arn, (
        f"restored queue should now reference the real policy, "
        f"got {restored_jq.get('schedulingPolicyArn')!r} != {target_arn!r}"
    )


def _retry_delete(fn, timeout_s=300.0):
    """Run a Batch delete; retry its ClientException refusals every 2 s to timeout_s while a
    dependent finishes deleting. A "does not exist" answer is done; every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_jq_gone(batch, name, timeout_s=300.0):
    """Poll every 2 s until DescribeJobQueues lists the queue absent or DELETED."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        queues = batch.describe_job_queues(jobQueues=[name])["jobQueues"]
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(2)
    raise AssertionError(f"job queue {name} still present {timeout_s:.0f}s after DeleteJobQueue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
