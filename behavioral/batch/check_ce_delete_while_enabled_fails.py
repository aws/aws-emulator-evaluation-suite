"""ce-delete-while-enabled-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "ce-delete-while-enabled-fails"
GROUP = 'overly-permissive'
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
    """Call fn(); return its botocore Error (code, message, request id).

    An unexpected SUCCESS raises: accepting input AWS refuses is reported as such, not as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
    """Detach the managed policy then delete an IAM role (best-effort)."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


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


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it (best-effort).

    A no-op when the CE is already gone: the run itself deletes it on the success path, and
    waiting on a status that a deleted CE can never report would otherwise burn the full
    poll timeout and starve cleanups registered after this one (ctx.on_cleanup's shared budget).
    """
    if _describe_ce(bat, name) is None:
        return
    _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))


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
    """Deleting a compute environment that is still ENABLED must fail (must disable first);
    disabling it then lets the identical delete call succeed (positive control + restore)."""
    bat = ctx.client("batch")
    name, _arn = _create_unmanaged_ce(ctx, bat, state="ENABLED")
    ce = _wait_ce_status(bat, name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", f"compute environment did not reach VALID: {ce!r}"

    code, message, request_id = _err_code(lambda: bat.delete_compute_environment(computeEnvironment=name))
    assert code == "ClientException", f"expected ClientException deleting an ENABLED CE, got {code!r}"
    expected_message = (
        "Cannot delete an enabled compute environment, set the state to DISABLED first."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ce = _describe_ce(bat, name)
    assert ce is not None and ce["status"] != "DELETED", "CE must not have been deleted"

    # Restore: disable the CE, then the identical delete call succeeds.
    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    disabled = _wait_ce_status(bat, name, {"VALID", "INVALID"})
    assert disabled["state"] == "DISABLED", f"CE did not settle into DISABLED: {disabled!r}"

    bat.delete_compute_environment(computeEnvironment=name)
    gone = _poll_until(
        lambda: _describe_ce(bat, name),
        lambda c: c is None,
        timeout_s=120,
        interval_s=3,
        description=f"compute environment {name} deleted",
    )
    assert gone is None, "compute environment still describable after the accepted delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
