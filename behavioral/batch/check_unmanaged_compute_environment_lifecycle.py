"""unmanaged-compute-environment-lifecycle."""

from __future__ import annotations
import json
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "unmanaged-compute-environment-lifecycle"
GROUP = 'compute-environment'
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


def _undo(fn, retry_s=0.0):
    """Run a teardown step; a resource that does not exist is done. Batch's ClientException for a
    resource still in use is retried every 2 s for retry_s; anything else raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "NoSuchEntity" or (
                err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")
            ):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


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


def _wait_ce_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _error(fn):
    """Run fn(); return the botocore Error dict, or raise if it unexpectedly succeeded."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("expected a ClientError, call succeeded")


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role."""
    iam = ctx.client("iam")
    _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _undo(lambda: iam.delete_role(RoleName=role_name))


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UNMANAGED CE: CREATING -> VALID, ENABLED<->DISABLED toggle, then delete -> DELETED."""
    bat = ctx.client("batch")
    name, arn = _create_unmanaged_ce(ctx, bat, state="ENABLED")

    ce = _wait_ce_status(bat, name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", f"expected VALID, got {ce['status']!r}: {ce.get('statusReason')}"
    assert ce["state"] == "ENABLED", f"expected state ENABLED, got {ce['state']!r}"
    assert ce["computeEnvironmentArn"] == arn, f"expected arn {arn!r}, got {ce['computeEnvironmentArn']!r}"
    assert ce["type"] == "UNMANAGED", f"expected type UNMANAGED, got {ce['type']!r}"

    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    # Poll on the *observed state*, not just status: immediately after the
    # update call the CE can still read status=VALID/state=ENABLED before it
    # flips to UPDATING, so waiting on status alone races.
    ce = _poll_until(lambda: _describe_ce(bat, name), lambda ce: ce is not None and ce.get("state") == "DISABLED" and ce.get("status") in ("VALID", "INVALID"), timeout_s=120, interval_s=3, description="compute environment DISABLED and settled")
    assert ce["state"] == "DISABLED", f"expected state DISABLED, got {ce['state']!r}"

    bat.delete_compute_environment(computeEnvironment=name)
    deleted = _poll_until(lambda: _describe_ce(bat, name), lambda ce: ce is None or ce.get("status") == "DELETED", timeout_s=120, interval_s=3, description="compute environment deleted")
    assert deleted is None or deleted["status"] == "DELETED", f"expected gone or DELETED, got {deleted!r}"

    # The dead id is not just absent from the read path; it is unusable for mutation too.
    error = _error(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    code, message = error.get("Code"), error.get("Message")
    assert code == "ClientException", f"expected ClientException updating a deleted CE, got {code!r}"
    assert message == f"{arn} does not exist", (
        f"expected the exact does-not-exist message naming {arn!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
