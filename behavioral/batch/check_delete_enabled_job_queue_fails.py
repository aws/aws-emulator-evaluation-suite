"""delete-enabled-job-queue-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "delete-enabled-job-queue-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_VPC_CACHE: dict = {}
_BATCH_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
_BATCH_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "batch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_FARGATE_EXEC_ROLE_NAME = "sim2real-behav-batch-exec-role"
_ECS_TASK_EXECUTION_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)
_ECS_TASKS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _swallow(fn):
    """Run fn(), treating only the resource's not-found answers as already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _err_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _wait_ce_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role; a failure raises."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _unmanaged_service_role_arn(ctx):
    """Create this run's own Batch service role for UNMANAGED CEs; returns its ARN. A role shared
    by name could be deleted by another run's cleanup while this run's compute environment uses it."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-svc-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _BATCH_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BATCH_SERVICE_POLICY)
    return arn


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _teardown_ce(ctx, bat, name):
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"),
        lambda: bat.delete_compute_environment(computeEnvironment=name),
    ]
    while True:
        listed = [
            ce
            for ce in bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
            if ce.get("status") != "DELETED"
        ]
        if not listed:
            return
        if steps and listed[0].get("status") != "DELETING":
            try:
                steps[0]()
                steps.pop(0)
                continue
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                    return
                if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise TimeoutError(f"compute environment {name} still listed at the cleanup deadline")
        time.sleep(2)


def _teardown_jq(ctx, bat, name):
    """Disable a job queue, wait for it to settle, then delete it; a failure raises."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _swallow(lambda: bat.delete_job_queue(jobQueue=name))


def _create_unmanaged_ce(ctx, bat, name=None, state="ENABLED"):
    """UNMANAGED CE (no computeResources / VPC): jobs park in RUNNABLE. Registers teardown.

    A freshly-created IAM role is not instantly assumable by Batch, so the 400 that reports
    exactly that is retried rather than trusting a fixed sleep.
    """
    name = name or ctx.unique_name("sim2real-behav-ce-unmgd-")
    role = _unmanaged_service_role_arn(ctx)
    last_exc = None
    for attempt in range(8):
        try:
            resp = bat.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state=state,
                serviceRole=role,
                tags=_MANAGED_TAGS,
            )
            break
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            transient = (
                "cannot be assumed" in msg
                or "not authorized to perform: sts:assumerole" in msg
                or "does not have permission" in msg
                or "invalid" in msg and "role" in msg
            )
            if not transient or attempt == 7:
                raise
            last_exc = exc
            time.sleep(5)
    else:  # pragma: no cover - loop always breaks or raises
        raise last_exc  # type: ignore[misc]
    ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, name))
    return name, resp["computeEnvironmentArn"]


def _create_job_queue(ctx, bat, ce_arn, name=None, priority=10, state="ENABLED", scheduling_policy_arn=None):
    name = name or ctx.unique_name("sim2real-behav-jq-")
    kwargs = dict(
        jobQueueName=name,
        state=state,
        priority=priority,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    return name, resp["jobQueueArn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A job queue in ENABLED state cannot be deleted; it must be DISABLED first (overly-permissive
    boundary). Positive control: the identical delete call succeeds once the queue is disabled."""
    bat = ctx.client("batch")
    ce_name, ce_arn = _create_unmanaged_ce(ctx, bat)
    _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    jq_name, _ = _create_job_queue(ctx, bat, ce_arn, state="ENABLED")
    _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})

    code, message = _err_code(lambda: bat.delete_job_queue(jobQueue=jq_name))
    assert code == "ClientException", f"expected ClientException deleting an ENABLED queue, got {code!r}"
    expected = "Cannot delete an enabled job queue, set the state to DISABLED first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    jq = _describe_jq(bat, jq_name)
    assert jq is not None and jq["status"] != "DELETED"

    # Restore leg: disabling submissions is the one thing that changes, and the identical
    # delete call must now succeed, proving the rejection above was state-specific.
    bat.update_job_queue(jobQueue=jq_name, state="DISABLED")
    disabled = _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})
    assert disabled["state"] == "DISABLED", f"expected DISABLED after update, got {disabled['state']!r}"

    bat.delete_job_queue(jobQueue=jq_name)
    gone = _poll_until(
        lambda: _describe_jq(bat, jq_name),
        lambda q: q is None,
        timeout_s=90,
        interval_s=3,
        description=f"job queue {jq_name} deleted",
    )
    assert gone is None, "job queue still describable after a delete that should have succeeded"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
