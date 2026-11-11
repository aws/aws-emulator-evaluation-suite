"""job-queue-state-time-limit-action-max-time-seconds-range-enforced."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-queue-state-time-limit-action-max-time-seconds-range-enforced"
GROUP = "job-lifecycle"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
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
# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association and each update
_JOB_RUNNABLE_S = 180  # SUBMITTED -> PENDING -> RUNNABLE needs no capacity
_TEARDOWN_S = 300      # DISABLED -> settle -> deleted -> gone, per resource
# The batch suite's cleanup budget (900 s), one deadline shared by every Batch delete of a run.
_TEARDOWN_RETRY_S = 900.0

_STUCK_REASON = "MISCONFIGURATION:COMPUTE_ENVIRONMENT_MAX_RESOURCE"
# maxTimeSeconds ranges from 600 (10 minutes) to 86,400 (24 hours).
_MIN_TIME_S = 600
_MAX_TIME_S = 86400
_STACK_VCPUS = 1       # the CE caps at 1 vCPU ...
_JOB_VCPU = "4"        # ... and the job asks for 4, so it can never be placed
_JOB_MEMORY = "8192"   # Fargate's 4-vCPU tier accepts 8192-30720 MB


def _action(max_time_s):
    return {
        "reason": _STUCK_REASON,
        "state": "RUNNABLE",
        "maxTimeSeconds": max_time_s,
        "action": "CANCEL",
    }


def _swallow(fn):
    """Run fn(); ignore only not-found answers (IAM NoSuchEntity, Batch 'does not exist') and
    raise every other error."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "NoSuchEntity" and not (
            err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); RAISE on deadline miss, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _wait_role_readable(ctx, role_name):
    """Bounded wait for a freshly-minted role to be readable by IAM's own read path."""
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=60,
        interval_s=3,
        description=f"IAM role {role_name} readable after create",
    )


def _fargate_execution_role_arn(ctx):
    """Create this run's ECS task execution role for Fargate Batch jobs; returns its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    _wait_role_readable(ctx, role_name)
    return arn


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (required by a MANAGED CE). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
    _wait_role_readable(ctx, "AWSServiceRoleForBatch")
    return resp["Role"]["Arn"]


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


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _delete_retrying(call, teardown_deadline):
    """Run a Batch delete; retry its ClientException refusals every 2 s to the shared deadline.

    A queue still draining or a compute environment still referenced refuses the delete with
    ClientException; an already-deleted resource returns; every other error raises.
    """
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_job(bat, job_id):
    """Terminate the job and wait for it to be terminal, so its queue can be deleted."""
    _swallow(lambda: bat.terminate_job(jobId=job_id, reason="behavioral-test-cleanup"))
    _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"job {job_id} terminal before queue teardown",
    )


def _teardown_jq(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    if _describe_jq(bat, name) is None:
        return
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S)
    _delete_retrying(lambda: bat.delete_job_queue(jobQueue=name), teardown_deadline)
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    if _describe_ce(bat, name) is None:
        return
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S)
    _delete_retrying(lambda: bat.delete_compute_environment(computeEnvironment=name), teardown_deadline)
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"compute environment {name} gone",
    )


def _fargate_ce(ctx, bat, teardown_deadline):
    """A MANAGED/FARGATE CE capped at 1 vCPU, polled to VALID. Returns its ARN."""
    net = ctx.network()
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    resp = bat.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_service_linked_role_arn(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": _STACK_VCPUS,
            "subnets": net.subnet_ids[:3],
            "securityGroupIds": [net.security_group_id],
        },
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name, teardown_deadline))
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} must reach VALID, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )
    return resp["computeEnvironmentArn"]


def _create_queue(ctx, bat, ce_arn, teardown_deadline, max_time_s):
    """CreateJobQueue with one time-limit action; returns the queue name, cleanup registered."""
    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        jobStateTimeLimitActions=[_action(max_time_s)],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name, teardown_deadline))
    return jq_name


def _queue_refused(ctx, bat, ce_arn, teardown_deadline, max_time_s):
    """CreateJobQueue with an out-of-range maxTimeSeconds; return the refusal's (code, message)."""
    try:
        jq_name = _create_queue(ctx, bat, ce_arn, teardown_deadline, max_time_s)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"CreateJobQueue accepted maxTimeSeconds={max_time_s} and created {jq_name}"
    )


def _register_unplaceable_jd(ctx, bat):
    """A FARGATE job definition demanding more vCPU than the CE in this check offers."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["true"],
            "executionRoleArn": _fargate_execution_role_arn(ctx),
            "resourceRequirements": [
                {"type": "VCPU", "value": _JOB_VCPU},
                {"type": "MEMORY", "value": _JOB_MEMORY},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
        },
        tags=dict(_MANAGED_TAGS),
    )
    job_def = f"{name}:{resp['revision']}"
    ctx.on_cleanup(lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=job_def)))
    return job_def


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateJobQueue refuses a jobStateTimeLimitAction with maxTimeSeconds 599 or 86401, keeps one
    at the 600 s minimum and, after UpdateJobQueue, at the 86400 s maximum exactly as set, and the
    armed queue holds an unplaceable job in RUNNABLE with no attempts.

    Reference: https://docs.aws.amazon.com/batch/latest/APIReference/API_JobStateTimeLimitAction.html
    """
    bat = ctx.client("batch")
    teardown_deadline: dict = {}
    ce_arn = _fargate_ce(ctx, bat, teardown_deadline)

    for max_time_s in (_MIN_TIME_S - 1, _MAX_TIME_S + 1):
        code, message = _queue_refused(ctx, bat, ce_arn, teardown_deadline, max_time_s)
        assert code == "ClientException", (
            f"maxTimeSeconds={max_time_s}: expected ClientException, got {code}: {message!r}"
        )
        expected = (
            f"Invalid job action wait time. Value must be in range: [{_MIN_TIME_S}..{_MAX_TIME_S}]"
        )
        assert message == expected, (
            f"maxTimeSeconds={max_time_s}: expected message {expected!r}, got {message!r}"
        )

    queue = _create_queue(ctx, bat, ce_arn, teardown_deadline, _MIN_TIME_S)
    jq = _wait_jq(bat, queue, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {queue} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    assert jq["jobStateTimeLimitActions"] == [_action(_MIN_TIME_S)], (
        f"DescribeJobQueues must report the action as created, got {jq['jobStateTimeLimitActions']!r}"
    )

    bat.update_job_queue(jobQueue=queue, jobStateTimeLimitActions=[_action(_MAX_TIME_S)])
    jq = _wait_jq(bat, queue, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {queue} must settle VALID after the update, got {jq['status']!r}: "
        f"{jq.get('statusReason')!r}"
    )
    assert jq["jobStateTimeLimitActions"] == [_action(_MAX_TIME_S)], (
        f"DescribeJobQueues must report the updated action, got {jq['jobStateTimeLimitActions']!r}"
    )

    job_def = _register_unplaceable_jd(ctx, bat)
    job_id = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=queue, jobDefinition=job_def
    )["jobId"]
    ctx.on_cleanup(lambda: _teardown_job(bat, job_id))

    job = _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") not in ("SUBMITTED", "PENDING"),
        timeout_s=_JOB_RUNNABLE_S,
        interval_s=5,
        description=f"job {job_id} left SUBMITTED/PENDING",
    )
    assert job["status"] == "RUNNABLE", (
        f"a job needing {_JOB_VCPU} vCPU on a queue whose only CE caps at {_STACK_VCPUS} must wait "
        f"in RUNNABLE, got {job['status']!r} (statusReason={job.get('statusReason')!r})"
    )
    assert not job.get("attempts"), (
        f"the unplaceable job must record no attempts, got {job.get('attempts')!r}"
    )
    assert "startedAt" not in job, f"the unplaceable job must have no startedAt, got {job.get('startedAt')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
