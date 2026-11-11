"""delete-referenced-compute-environment-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "delete-referenced-compute-environment-fails"
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


def _wait_jq_gone(bat, name, timeout_s=90, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} gone",
    )


def _wait_ce_gone(bat, name, timeout_s=90, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} gone",
    )


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
    # Assumability propagation delay is handled by the retry loop in _create_unmanaged_ce,
    # which already retries on "cannot be assumed"-style errors with backoff.
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
    """Disable a compute environment, wait for it to settle, then delete it; a failure raises."""
    # The body deletes this CE itself, so a CE already gone (or DELETED) needs nothing more.
    if _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED")) is None:
        return
    ce = _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None or ce.get("status") in ("VALID", "INVALID", "DELETED"),
        timeout_s=90, interval_s=2, description=f"compute environment {name} settled or gone",
    )
    if ce is None or ce["status"] == "DELETED":
        return
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))


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
    """A CE referenced by a job queue cannot be deleted, even once the CE itself is DISABLED
    (isolating the job-queue reference, not the CE's own ENABLED state, as the blocker); removing
    the reference is what lets the identical delete call succeed."""
    bat = ctx.client("batch")
    ce_name, ce_arn = _create_unmanaged_ce(ctx, bat)
    _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    jq_name, _ = _create_job_queue(ctx, bat, ce_arn, state="ENABLED")
    _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})

    # Disable the CE itself first so a rejection here cannot be attributed to it still being ENABLED
    # -- the only thing left standing between this CE and deletion is the job queue's reference.
    bat.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
    _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})

    code, message = _err_code(lambda: bat.delete_compute_environment(computeEnvironment=ce_name))
    assert code == "ClientException", (
        f"expected ClientException deleting a disabled CE still referenced by a job queue, got {code!r}"
    )
    expected = "Cannot delete, found existing JobQueue relationship."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The CE must still exist and be usable afterwards (delete must be a no-op on failure).
    ce = _describe_ce(bat, ce_name)
    assert ce is not None and ce["status"] != "DELETED", f"CE must not have been deleted, got {ce!r}"

    # Restore: remove the reference (disable then delete the job queue), then prove the
    # identical delete call now succeeds and the CE is actually gone.
    bat.update_job_queue(jobQueue=jq_name, state="DISABLED")
    _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})
    last_exc = None
    for _ in range(5):
        try:
            bat.delete_job_queue(jobQueue=jq_name)
            last_exc = None
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    if last_exc is not None:
        raise AssertionError(f"could not delete job queue {jq_name} to clear the reference: {last_exc}")
    _wait_jq_gone(bat, jq_name)

    bat.delete_compute_environment(computeEnvironment=ce_name)
    gone = _wait_ce_gone(bat, ce_name)
    assert gone is None, f"CE {ce_name} still describable after a delete that should have succeeded"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
