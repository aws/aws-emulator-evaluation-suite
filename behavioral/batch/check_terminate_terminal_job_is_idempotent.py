"""terminate-terminal-job-is-idempotent."""

from __future__ import annotations
import json
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "terminate-terminal-job-is-idempotent"
GROUP = 'job-lifecycle'
SERVICES = ['batch']

def _unmanaged_queue(ctx, bat):
    """Provision CE + ENABLED queue on an UNMANAGED CE. Returns (jq_name, jq_arn)."""
    ce_name, ce_arn = _create_unmanaged_ce(ctx, bat)
    ce = _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", f"CE not VALID: {ce.get('statusReason')}"
    jq_name, jq_arn = _create_job_queue(ctx, bat, ce_arn, state="ENABLED")
    jq = _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", f"queue not VALID: {jq.get('statusReason')}"
    return jq_name, jq_arn

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
    """Run fn(), swallowing any exception (best-effort setup step)."""
    try:
        fn()
    except Exception:
        pass


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


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


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


def _wait_job_status(bat, job_id, statuses, timeout_s=180, interval_s=3):
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job {job_id} status in {sorted(statuses)}",
    )


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role."""
    iam = ctx.client("iam")
    _undo(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _undo(lambda: iam.delete_role(RoleName=role_name))


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


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it."""
    _undo(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    _undo(lambda: bat.delete_compute_environment(computeEnvironment=name), retry_s=60)


def _teardown_jq(ctx, bat, name):
    """Disable a job queue, wait for it to settle, then delete it."""
    _undo(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    _undo(lambda: bat.delete_job_queue(jobQueue=name))
    # DeleteJobQueue is asynchronous; its compute environment refuses deletion until it is gone.
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None or jq.get("status") == "DELETED",
        timeout_s=300,
        interval_s=2,
        description=f"job queue {name} deleted",
    )


def _deregister_jd(bat, name, revision):
    _undo(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


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


def _register_job_definition(ctx, bat, name=None, command=None):
    name = name or ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": command or ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


def _submit_job(ctx, bat, queue, job_definition, name=None, depends_on=None):
    name = name or ctx.unique_name("sim2real-behav-job-")
    kwargs = dict(jobName=name, jobQueue=queue, jobDefinition=job_definition)
    if depends_on:
        kwargs["dependsOn"] = depends_on
    resp = bat.submit_job(**kwargs)
    job_id = resp["jobId"]
    ctx.on_cleanup(
        lambda: _undo(lambda: bat.terminate_job(jobId=job_id, reason="behavioral-test-cleanup"))
    )
    return job_id, resp["jobArn"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateJob on an already-FAILED job is accepted and does not change state.

    Terminal states in Batch are absorbing: re-terminating must neither error
    nor resurrect/re-stamp the job.
    """
    bat = ctx.client("batch")
    jq_name, jq_arn = _unmanaged_queue(ctx, bat)
    jd_name, jd_arn, revision = _register_job_definition(ctx, bat)
    job_id, _ = _submit_job(ctx, bat, jq_name, jd_arn)
    _wait_job_status(bat, job_id, {"RUNNABLE"}, timeout_s=120, interval_s=3)

    bat.terminate_job(jobId=job_id, reason="behavioral-test-terminate-1")
    first = _wait_job_status(bat, job_id, {"FAILED"}, timeout_s=120, interval_s=3)

    # Second terminate against the terminal job must be a no-op, not an error.
    bat.terminate_job(jobId=job_id, reason="behavioral-test-terminate-2")
    second = _describe_job(bat, job_id)
    assert second["status"] == "FAILED", f"terminal job changed state on re-terminate: {second['status']!r}"
    assert second.get("stoppedAt") == first.get("stoppedAt"), (
        "re-terminating a terminal job must not re-stamp stoppedAt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
