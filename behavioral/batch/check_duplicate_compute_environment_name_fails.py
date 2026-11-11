"""duplicate-compute-environment-name-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "duplicate-compute-environment-name-fails"
GROUP = 'error-semantics'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_VPC_CACHE: dict = {}
_UNMANAGED_ROLE_NAME = "sim2real-behav-batch-service-role"
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
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.
    Unexpected success raises, so an accepted call is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role, retrying DeleteConflict: a detach is
    not always immediately visible to the following delete_role."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    deadline = time.monotonic() + 30
    while True:
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _unmanaged_service_role_arn(ctx):
    """Create-or-reuse the customer-managed Batch service role (UNMANAGED CEs); returns its ARN.

    Registers deletion cleanup only if THIS check created it, so no sim2real-* IAM residue is left.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_role(
            RoleName=_UNMANAGED_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
            Tags=_tags_kv(),
        )
        arn = resp["Role"]["Arn"]
    except Exception as exc:
        try:
            return iam.get_role(RoleName=_UNMANAGED_ROLE_NAME)["Role"]["Arn"]
        except Exception:
            raise AssertionError(
                f"cannot create/resolve a customer-managed Batch service role: {exc}"
            ) from exc
    _swallow(lambda: iam.attach_role_policy(RoleName=_UNMANAGED_ROLE_NAME, PolicyArn=_BATCH_SERVICE_POLICY))
    ctx.on_cleanup(lambda: _delete_role(ctx, _UNMANAGED_ROLE_NAME, _BATCH_SERVICE_POLICY))
    return arn


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it; a failure raises.

    Short-circuits if the name is already gone, so a check that tears one down mid-body doesn't
    also burn a full settle-wait against this same name's registered cleanup at suite end.
    """
    if _describe_ce(bat, name) is None:
        return
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    _retry_client_exception(lambda: bat.delete_compute_environment(computeEnvironment=name))


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second CE with an already-used name is rejected (namespace conflict); once
    the original is actually deleted the name is released and the identical create succeeds."""
    bat = ctx.client("batch")
    name, arn = _create_unmanaged_ce(ctx, bat)
    _wait_ce_status(bat, name, {"VALID", "INVALID"})

    role = _unmanaged_service_role_arn(ctx)
    code, message = _error(lambda: bat.create_compute_environment(
        computeEnvironmentName=name,
        type="UNMANAGED",
        state="ENABLED",
        serviceRole=role,
    ))
    assert code == "ClientException", f"expected ClientException for duplicate name, got {code!r}"
    assert message == "Object already exists", f"expected message 'Object already exists', got {message!r}"

    # The original must be untouched by the rejected create.
    ce = _describe_ce(bat, name)
    assert ce is not None and ce["status"] != "DELETED" and ce["computeEnvironmentArn"] == arn, (
        f"original CE {name!r} (arn {arn}) mutated or removed by the rejected duplicate create: {ce!r}"
    )

    # Restore: the conflict is with the LIVE resource, not the name forever. Delete the
    # original, wait for it to actually be gone, then the identical create must now succeed.
    _teardown_ce(ctx, bat, name)
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda result: result is None,
        timeout_s=120,
        interval_s=3,
        description=f"compute environment {name} fully removed",
    )
    # Direct call, not _create_unmanaged_ce: the role has had a full CE lifecycle to propagate
    # by now, and the original create's cleanup (bound to this same `name`) already covers
    # whatever CE holds it at teardown time — a second registration would double the cleanup
    # phase's work against its own budget.
    resp = bat.create_compute_environment(
        computeEnvironmentName=name,
        type="UNMANAGED",
        state="ENABLED",
        serviceRole=role,
        tags=_MANAGED_TAGS,
    )
    assert resp.get("computeEnvironmentArn"), (
        f"recreating released name {name!r} did not return an ARN: {resp!r}"
    )
    _wait_ce_status(bat, name, {"VALID", "INVALID"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
