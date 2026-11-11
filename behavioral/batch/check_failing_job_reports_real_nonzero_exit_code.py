"""failing-job-reports-real-nonzero-exit-code."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failing-job-reports-real-nonzero-exit-code"
GROUP = 'data-plane'
SERVICES = ['batch']

# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
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
# Bounded deadlines, each with its reason; a wait never stands in for an assertion.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> VALID -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run


def _swallow(fn):
    """Run fn(); only a resource that is already gone is ignored, every other failure raises."""
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


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role; a failure raises."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create-or-reuse the ECS task execution role for Fargate Batch jobs; returns its ARN.

    Deletion cleanup is registered only when THIS check created the role, so a shared
    pre-existing role is never reaped out from under a concurrent check.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_role(
            RoleName=_FARGATE_EXEC_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch Fargate task execution role",
            Tags=_tags_kv(),
        )
        arn = resp["Role"]["Arn"]
    except Exception as exc:
        try:
            return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
        except Exception:
            raise AssertionError(
                f"cannot create/resolve the Fargate task execution role: {exc}"
            ) from exc
    _swallow(lambda: iam.attach_role_policy(RoleName=_FARGATE_EXEC_ROLE_NAME, PolicyArn=_ECS_TASK_EXECUTION_POLICY))
    ctx.on_cleanup(lambda: _delete_role(ctx, _FARGATE_EXEC_ROLE_NAME, _ECS_TASK_EXECUTION_POLICY))
    # No unconditional wait here: IAM propagation to ECS exposes no condition to poll, and the
    # CE + job-queue provisioning that runs before any job is submitted (both up to 300s) already
    # buys far more settle time than a fixed sleep would.
    return arn


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


_VPC_CACHE: dict = {}


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from the account's default VPC.

    Cached per region so an explicit call and the CE creation observe identical values.
    Raises AssertionError (a FAIL, never a skip) when the account lacks a usable default VPC:
    the invariant is unmeasurable without one, and fabricating subnet ids would be a lie.
    """
    if ctx.region in _VPC_CACHE:
        return _VPC_CACHE[ctx.region]
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    except Exception as exc:
        raise AssertionError(f"cannot describe VPCs in this account: {exc}") from exc
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; cannot build a MANAGED Fargate CE")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not subnet_ids:
        raise AssertionError(f"shared network {vpc_id} has no usable subnets")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"shared network {vpc_id} has no default security group")
    _VPC_CACHE[ctx.region] = (subnet_ids[:3], sgs[0]["GroupId"])
    return _VPC_CACHE[ctx.region]


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (valid for MANAGED CEs). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
        return resp["Role"]["Arn"]
    except Exception as exc:
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get("computeEnvironments", [])
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


def _wait_ce_status(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq_status(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _wait_job_status(bat, job_id, statuses, timeout_s=_JOB_TERMINAL_S, interval_s=10):
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job {job_id} status in {sorted(statuses)}",
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A compute environment cannot be deleted while a queue references it and a queue
    cannot be deleted while it holds non-terminal jobs, so this MUST complete before
    the queue teardown runs. Registered before the queue, so ctx reverse order runs it first.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _poll_until(
            lambda jid=jid: _describe_job(bat, jid),
            lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job {jid} terminal before queue teardown",
        )


def _retry_client_exception(call, timeout_s=60):
    """Retry a call Batch refuses with ClientException while a dependency settles, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _teardown_jq(bat, name):
    """DISABLE -> poll VALID -> DeleteJobQueue -> poll gone.

    Skipping either poll is what leaks: DeleteJobQueue on an ENABLED queue is a 400, and
    DeleteComputeEnvironment on a still-referenced CE is a 400, so the CE would survive.
    """
    if _describe_jq(bat, name) is None:
        return
    bat.update_job_queue(jobQueue=name, state="DISABLED")
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=3)
    _retry_client_exception(lambda: bat.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    if _describe_ce(bat, name) is None:
        return
    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=5)
    _retry_client_exception(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"compute environment {name} gone",
    )


def _delete_log_streams(ctx, stream_names):
    """Delete the /aws/batch/job log streams this check's attempts created.

    The log GROUP /aws/batch/job is AWS-managed and shared by every Batch job in the
    account, so deleting the group would be a cross-tenant hazard. Only the streams
    this check minted are reaped.
    """
    if not stream_names:
        return
    logs = ctx.client("logs")
    for s in sorted(set(stream_names)):
        _swallow(lambda s=s: logs.delete_log_stream(logGroupName="/aws/batch/job", logStreamName=s))


def _collect_log_streams(job):
    """Every logStreamName a job's attempts reported (may be empty if it never started)."""
    out = []
    for att in job.get("attempts") or []:
        name = (att.get("container") or {}).get("logStreamName")
        if name:
            out.append(name)
    name = (job.get("container") or {}).get("logStreamName")
    if name:
        out.append(name)
    return out


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE CE + ENABLED queue, both polled to VALID. Returns (jq_name, ce_arn).

    FARGATE (not EC2) on purpose: a MANAGED/EC2 CE with minvCpus > 0 keeps instances alive
    forever, which is the classic Batch cost leak. FARGATE has no minvCpus floor, so an
    idle CE costs nothing; maxvCpus only caps concurrency.
    Teardowns are registered at creation time, CE first then queue, so ctx's reverse order
    tears down queue-then-CE.
    """
    subnets, sg = _default_vpc_networking(ctx)
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    service_role = _service_linked_role_arn(ctx)

    # A just-created AWSServiceRoleForBatch has no observable readiness condition to poll, so
    # retry the actual call that needs it (bounded, with the original error surfaced on timeout)
    # rather than guessing a fixed settle.
    resp, last_exc, deadline = None, None, time.monotonic() + 60
    while resp is None and time.monotonic() < deadline:
        try:
            resp = bat.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="MANAGED",
                state="ENABLED",
                serviceRole=service_role,
                computeResources={
                    "type": "FARGATE",
                    "maxvCpus": max_vcpus,
                    "subnets": subnets,
                    "securityGroupIds": [sg],
                },
                tags=_MANAGED_TAGS,
            )
        except Exception as exc:  # IAM propagation lag; retry until the budget runs out
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(
            f"CreateComputeEnvironment never succeeded within 60s of resolving "
            f"AWSServiceRoleForBatch (IAM propagation?): {last_exc!r}"
        )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce_arn = resp["computeEnvironmentArn"]
    ce = _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", f"CE not VALID: {ce.get('statusReason')!r}"

    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", f"queue not VALID: {jq.get('statusReason')!r}"
    return jq_name, ce_arn


def _fargate_container_properties(ctx, command, vcpu="0.25", memory="512"):
    return {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command,
        "executionRoleArn": _fargate_execution_role_arn(ctx),
        "resourceRequirements": [
            {"type": "VCPU", "value": vcpu},
            {"type": "MEMORY", "value": memory},
        ],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
        "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
    }


def _register_fargate_jd(ctx, bat, command, *, retry_strategy=None, timeout=None,
                         parameters=None, vcpu="0.25", memory="512"):
    """Register a FARGATE job definition. Returns (name, arn, revision)."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=_fargate_container_properties(ctx, command, vcpu=vcpu, memory=memory),
        tags=_MANAGED_TAGS,
    )
    if retry_strategy:
        kwargs["retryStrategy"] = retry_strategy
    if timeout:
        kwargs["timeout"] = timeout
    if parameters:
        kwargs["parameters"] = parameters
    resp = bat.register_job_definition(**kwargs)
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


def _tracked_submit(ctx, bat, queue, job_definition, **kwargs):
    """SubmitJob with a cleanup registered at submit time. Returns the jobId."""
    name = ctx.unique_name("sim2real-behav-job-")
    resp = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_definition, **kwargs)
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _log_stream_sink(ctx):
    """Register log-stream reaping up front; the run body appends the names it observes."""
    streams: list = []
    ctx.on_cleanup(lambda: _delete_log_streams(ctx, streams))
    return streams


_STATUS_RANK = {
    "SUBMITTED": 0,
    "PENDING": 1,
    "RUNNABLE": 2,
    "STARTING": 3,
    "RUNNING": 4,
    "SUCCEEDED": 5,
    "FAILED": 5,
}


def _trace_job_to_terminal(bat, job_id, *, timeout_s=_JOB_TERMINAL_S, interval_s=5):
    """Poll DescribeJobs recording the ORDERED sequence of distinct statuses observed.

    Returns (trace, final_job). Ordered, not a set: an emulator that reports states out of
    order (or reports a terminal state it never passed through) must be detectable.
    """
    trace: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = _describe_job(bat, job_id)
        if job is not None:
            st = job.get("status")
            if st and (not trace or trace[-1] != st):
                trace.append(st)
            if st in ("SUCCEEDED", "FAILED"):
                return trace, job
        time.sleep(interval_s)
    raise AssertionError(
        f"job {job_id} did not reach a terminal state within {timeout_s}s; trace={trace}"
    )


def _assert_monotonic(trace):
    """The observed status sequence must never go backwards through the Batch state machine."""
    ranks = [_STATUS_RANK[s] for s in trace if s in _STATUS_RANK]
    unknown = [s for s in trace if s not in _STATUS_RANK]
    assert not unknown, f"unmodelled job status(es) {unknown} in trace {trace}"
    assert ranks == sorted(ranks), f"job status went backwards: {trace}"

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A container exiting 17 makes the job FAILED with container.exitCode 17 and a statusReason, while
    the SAME job definition overridden to `exit 0` SUCCEEDS with 0: the exit code is the process's, not a constant.
    """
    bat = ctx.client("batch")
    streams = _log_stream_sink(ctx)
    queue, _ce_arn = _fargate_stack(ctx, bat)
    jd_name, _jd_arn, rev = _register_fargate_jd(ctx, bat, ["/bin/sh", "-c", "exit 17"])
    jd = f"{jd_name}:{rev}"

    fail_id = _tracked_submit(ctx, bat, queue, jd)
    ok_id = _tracked_submit(
        ctx, bat, queue, jd,
        containerOverrides={"command": ["/bin/sh", "-c", "exit 0"]},
    )

    failed = _wait_job_status(bat, fail_id, {"SUCCEEDED", "FAILED"})
    streams.extend(_collect_log_streams(failed))
    assert failed["status"] == "FAILED", (
        f"a container exiting 17 must make the job FAILED, got {failed['status']!r}"
    )
    fc = failed.get("container") or {}
    assert fc.get("exitCode") == 17, (
        f"expected container.exitCode == 17 (the real process status), got {fc.get('exitCode')!r}"
    )
    reason = failed.get("statusReason")
    assert isinstance(reason, str) and reason.strip(), (
        f"a FAILED job must carry a statusReason explaining the failure, got {reason!r}"
    )
    fattempts = failed.get("attempts") or []
    assert len(fattempts) == 1, f"no retryStrategy means exactly 1 attempt, got {len(fattempts)}"
    assert (fattempts[0].get("container") or {}).get("exitCode") == 17, (
        f"attempts[0] must carry the same exit code as the job, got {fattempts[0].get('container')!r}"
    )

    # Control: the SAME job definition, command overridden to exit 0, still succeeds with 0.
    ok = _wait_job_status(bat, ok_id, {"SUCCEEDED", "FAILED"})
    streams.extend(_collect_log_streams(ok))
    assert ok["status"] == "SUCCEEDED", (
        f"containerOverrides `exit 0` on the same job definition must SUCCEED, got "
        f"{ok['status']!r} reason={ok.get('statusReason')!r}"
    )
    assert (ok.get("container") or {}).get("exitCode") == 0, (
        f"control job must report exitCode 0, got {(ok.get('container') or {}).get('exitCode')!r} "
        "(a constant exit code for every job is the failure mode this pair detects)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
