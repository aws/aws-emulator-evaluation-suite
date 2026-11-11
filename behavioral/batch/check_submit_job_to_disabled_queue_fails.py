"""submit-job-to-disabled-queue-fails."""

from __future__ import annotations
import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "submit-job-to-disabled-queue-fails"
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


def _error(fn):
    """Call fn(); return its botocore Error dict plus the HTTP status. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return dict(exc.response.get("Error", {}), HTTPStatusCode=exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _wait_jq_state(bat, name, state, timeout_s=120, interval_s=3):
    """Wait until the queue has settled (VALID/INVALID) AND reports the requested state.

    `status` alone is not enough: a queue can read VALID while `state` is still the
    previous value mid-transition, which would let a submission race the disable.
    """
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in {"VALID", "INVALID"} and jq.get("state") == state,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} state == {state!r} and status stable",
    )


def _terminate_job(bat, job_id):
    """Terminate a job this check submitted and wait for a terminal state."""
    jobs = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    if jobs and jobs[0].get("status") not in ("SUCCEEDED", "FAILED"):
        bat.terminate_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
        _poll_until(
            lambda: bat.describe_jobs(jobs=[job_id])["jobs"][0],
            lambda j: j.get("status") in ("SUCCEEDED", "FAILED"),
            timeout_s=60,
            interval_s=3,
            description=f"job {job_id} reaching a terminal state after terminate",
        )


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role; only an already-gone role is tolerated."""
    iam = ctx.client("iam")
    for fn in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _unmanaged_service_role_arn(ctx):
    """Create this run's own customer-managed Batch service role (UNMANAGED CEs); returns its ARN."""
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
    # No fixed wait here: a brand-new role is not instantly assumable by Batch, and
    # _create_unmanaged_ce's bounded retry (on the "cannot be assumed" transient) is
    # what actually absorbs that lag.
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
    """Disable a job queue, wait for it to settle, then delete it."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _undo(lambda: bat.delete_job_queue(jobQueue=name))


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitJob against a DISABLED job queue is rejected and leaves no job in ListJobs, while the
    identical call succeeds before disabling and again after re-enabling the queue."""
    bat = ctx.client("batch")
    ce_name, ce_arn = _create_unmanaged_ce(ctx, bat)
    _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    jq_name, jq_arn = _create_job_queue(ctx, bat, ce_arn, state="ENABLED")
    _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})

    jd_name, jd_arn, revision = _register_job_definition(ctx, bat)

    # Positive control: the queue accepts submissions while ENABLED.
    control_name = ctx.unique_name("sim2real-behav-job-control-")
    control_id = bat.submit_job(jobName=control_name, jobQueue=jq_name, jobDefinition=jd_arn)["jobId"]
    ctx.on_cleanup(lambda: _terminate_job(bat, control_id))
    control_job = bat.describe_jobs(jobs=[control_id])["jobs"][0]
    assert control_job.get("jobName") == control_name and control_job.get("status") != "FAILED", (
        f"positive control submission against the ENABLED queue was not accepted, got "
        f"{control_job.get('jobName')!r} status {control_job.get('status')!r}"
    )

    # Break exactly one thing: disable the queue.
    bat.update_job_queue(jobQueue=jq_name, state="DISABLED")
    _wait_jq_state(bat, jq_name, "DISABLED")

    rejected_name = ctx.unique_name("sim2real-behav-job-rejected-")
    error = _error(lambda: bat.submit_job(
        jobName=rejected_name,
        jobQueue=jq_name,
        jobDefinition=jd_arn,
    ))
    code, status, message = error.get("Code"), error.get("HTTPStatusCode"), error.get("Message") or ""
    assert code == "ClientException", f"expected ClientException submitting to a DISABLED queue, got {code!r}"
    assert status == 400, f"expected HTTP 400 submitting to a DISABLED queue, got {status}"
    assert message == f"JobQueue {jq_arn} not ENABLED.", (
        f"expected the DISABLED-queue refusal message to name the queue ARN, got {message!r}"
    )

    # Effect absent: an independent read shows the rejected submission never landed.
    # A JOB_NAME filter lists every status, not only RUNNING.
    summaries = bat.list_jobs(
        jobQueue=jq_name, filters=[{"name": "JOB_NAME", "values": [rejected_name]}]
    )["jobSummaryList"]
    assert not any(s.get("jobName") == rejected_name for s in summaries), (
        f"job {rejected_name!r} appears in ListJobs despite the DISABLED-queue rejection: {summaries}"
    )

    # Restore: re-enable the queue and the identical call now succeeds.
    bat.update_job_queue(jobQueue=jq_name, state="ENABLED")
    _wait_jq_state(bat, jq_name, "ENABLED")

    restored_name = ctx.unique_name("sim2real-behav-job-restored-")
    restored_id = bat.submit_job(jobName=restored_name, jobQueue=jq_name, jobDefinition=jd_arn)["jobId"]
    ctx.on_cleanup(lambda: _terminate_job(bat, restored_id))

    restored_job = bat.describe_jobs(jobs=[restored_id])["jobs"][0]
    assert restored_job.get("jobName") == restored_name, (
        f"expected the independent read to name the restored job, got {restored_job.get('jobName')!r}"
    )
    assert restored_job.get("status") != "FAILED", (
        f"identical submission after re-enabling the queue FAILED: {restored_job.get('statusReason')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
