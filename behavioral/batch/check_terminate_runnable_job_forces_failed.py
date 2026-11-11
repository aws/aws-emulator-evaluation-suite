"""terminate-runnable-job-forces-failed."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "terminate-runnable-job-forces-failed"
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
    """Detach the managed policy, then delete the role; a missing one is already gone."""
    iam = ctx.client("iam")
    for step in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _unmanaged_service_role_arn(ctx):
    """A per-run customer-managed Batch service role for UNMANAGED CEs; returns its ARN. Deleted
    on teardown, after the CE that uses it is gone."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-batch-svc-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_BATCH_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch service role for UNMANAGED CEs",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name, _BATCH_SERVICE_POLICY))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BATCH_SERVICE_POLICY)
    return arn


#: A compute environment in either status is on its way out or gone.
_GONE = ("DELETING", "DELETED")


def _teardown_ce(ctx, bat, name):
    """Disable the compute environment, delete it once no queue references it, and wait until it
    is gone: its service role is deleted after this, and Batch needs the role until then."""
    _undo(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    deadline = time.monotonic() + 300
    while (_describe_ce(bat, name) or {"status": "DELETED"})["status"] not in _GONE:
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as exc:
            # A queue still being deleted keeps its CE relationship; anything else is a failure.
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None or ce.get("status") == "DELETED",
        timeout_s=600,
        interval_s=5,
        description=f"compute environment {name} gone",
    )


def _teardown_jq(ctx, bat, name):
    """Disable the job queue, delete it, and wait until it is gone, so its CE can be deleted."""
    _undo(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    _undo(lambda: bat.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None or jq.get("status") == "DELETED",
        timeout_s=300,
        interval_s=5,
        description=f"job queue {name} gone",
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
    """TerminateJob moves a queued (RUNNABLE) job to the FAILED terminal state."""
    bat = ctx.client("batch")
    jq_name, jq_arn = _unmanaged_queue(ctx, bat)
    jd_name, jd_arn, revision = _register_job_definition(ctx, bat)
    job_id, _ = _submit_job(ctx, bat, jq_name, jd_arn)

    _wait_job_status(bat, job_id, {"RUNNABLE"}, timeout_s=120, interval_s=3)

    reason = "behavioral-test-terminate"
    bat.terminate_job(jobId=job_id, reason=reason)

    job = _wait_job_status(bat, job_id, {"FAILED", "SUCCEEDED"}, timeout_s=120, interval_s=3)
    assert job["status"] == "FAILED", f"expected TerminateJob to force FAILED, got {job['status']!r}"
    assert job.get("statusReason") == reason, (
        f"expected statusReason to echo the caller-supplied reason {reason!r}, got {job.get('statusReason')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
