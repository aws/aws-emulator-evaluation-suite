"""job-retry-strategy-evaluate-on-exit-controls-attempt-count."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-retry-strategy-evaluate-on-exit-controls-attempt-count"
GROUP = 'data-plane'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_FARGATE_EXEC_ROLE_PREFIX = "sim2real-behav-batch-exec-"
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
# Bounded deadlines, each with its reason.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> VALID -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run


def _swallow(fn):
    """Run fn(); return on a not-found answer and raise every other error."""
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
    """Detach the managed policy, then delete an IAM role; an already-gone one is fine."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create this run's ECS task execution role for Fargate Batch jobs; returns its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(_FARGATE_EXEC_ROLE_PREFIX)
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)

    def _policy_attached():
        try:
            pols = iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
        except Exception:
            return False
        return any(p.get("PolicyArn") == _ECS_TASK_EXECUTION_POLICY for p in pols)

    _poll_until(
        _policy_attached,
        lambda ok: ok,
        timeout_s=20,
        interval_s=1,
        description="execution role policy attachment visible before Batch/ECS will assume it",
    )
    return arn


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


_VPC_CACHE: dict = {}


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from ctx.network().

    Cached per region so an explicit call and the CE creation observe identical values.
    Raises AssertionError when the network has no usable subnet or default security group.
    """
    held = _VPC_CACHE.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    except Exception as exc:
        raise AssertionError(f"cannot describe the network VPC: {exc}") from exc
    if not vpcs:
        raise AssertionError("the network VPC is not visible to DescribeVpcs; cannot build a MANAGED Fargate CE")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not subnet_ids:
        raise AssertionError(f"network VPC {vpc_id} has no usable subnets")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"network VPC {vpc_id} has no default security group")
    _VPC_CACHE[id(ctx)] = (ctx, (subnet_ids[:3], sgs[0]["GroupId"]))
    ctx.on_cleanup(lambda: _VPC_CACHE.pop(id(ctx), None))
    return _VPC_CACHE[id(ctx)][1]


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (valid for MANAGED CEs). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
    except Exception as exc:
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc

    def _slr_visible():
        try:
            iam.get_role(RoleName="AWSServiceRoleForBatch")
            return True
        except Exception:
            return False

    _poll_until(
        _slr_visible,
        lambda ok: ok,
        timeout_s=30,
        interval_s=2,
        description="Batch service-linked role visible before Batch will accept it",
    )
    return resp["Role"]["Arn"]


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


def _delete_retrying(call):
    """Run a Batch delete; retry its ClientException refusals every 2 s to _TEARDOWN_S.

    A queue still draining refuses the delete with ClientException; an already-deleted queue
    returns; every other error raises.
    """
    deadline = time.monotonic() + _TEARDOWN_S
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


def _teardown_jq(bat, name):
    """DISABLE -> poll VALID -> DeleteJobQueue -> poll gone.

    Skipping either poll is what leaks: DeleteJobQueue on an ENABLED queue is a 400, and
    DeleteComputeEnvironment on a still-referenced CE is a 400, so the CE would survive.
    """
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=3)
    _delete_retrying(lambda: bat.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=5)
    _delete_compute_environment_and_wait(bat, name)
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
    resp = bat.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_service_linked_role_arn(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg],
        },
        tags=_MANAGED_TAGS,
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


def _fargate_container_properties(exec_role_arn, command, vcpu="0.25", memory="512"):
    return {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command,
        "executionRoleArn": exec_role_arn,
        "resourceRequirements": [
            {"type": "VCPU", "value": vcpu},
            {"type": "MEMORY", "value": memory},
        ],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
        "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
    }


def _register_fargate_jd(ctx, bat, exec_role_arn, command, *, retry_strategy=None, timeout=None,
                         parameters=None, vcpu="0.25", memory="512"):
    """Register a FARGATE job definition. Returns (name, arn, revision)."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=_fargate_container_properties(exec_role_arn, command, vcpu=vcpu, memory=memory),
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With attempts=2 and a job exiting 3, evaluateOnExit onExitCode 3 -> RETRY ends FAILED after
    2 attempts (both exit 3, distinct tasks) and onExitCode 3 -> EXIT ends FAILED after 1 attempt:
    the matched rule's action decides whether a failed attempt is retried."""
    bat = ctx.client("batch")
    streams = _log_stream_sink(ctx)
    exec_role_arn = _fargate_execution_role_arn(ctx)
    queue, _ce_arn = _fargate_stack(ctx, bat)

    retry_name, _a, retry_rev = _register_fargate_jd(
        ctx, bat, exec_role_arn, ["/bin/sh", "-c", "exit 3"],
        retry_strategy={"attempts": 2, "evaluateOnExit": [{"onExitCode": "3", "action": "RETRY"}]},
    )
    exit_name, _b, exit_rev = _register_fargate_jd(
        ctx, bat, exec_role_arn, ["/bin/sh", "-c", "exit 3"],
        retry_strategy={"attempts": 2, "evaluateOnExit": [{"onExitCode": "3", "action": "EXIT"}]},
    )

    retried_id = _tracked_submit(ctx, bat, queue, f"{retry_name}:{retry_rev}")
    exited_id = _tracked_submit(ctx, bat, queue, f"{exit_name}:{exit_rev}")

    # 2 attempts of a Fargate task, so double the single-attempt budget.
    retried = _wait_job_status(bat, retried_id, {"SUCCEEDED", "FAILED"}, timeout_s=2 * _JOB_TERMINAL_S)
    streams.extend(_collect_log_streams(retried))
    assert retried["status"] == "FAILED", f"exit 3 must end FAILED, got {retried['status']!r}"
    rattempts = retried.get("attempts") or []
    assert len(rattempts) == 2, (
        f"onExitCode 3 -> RETRY with attempts=2 must record exactly 2 attempts, got "
        f"{len(rattempts)} (an emulator that ignores retryStrategy records 1); "
        f"statusReason={retried.get('statusReason')!r} container={retried.get('container')!r}"
    )
    for i, att in enumerate(rattempts):
        assert (att.get("container") or {}).get("exitCode") == 3, (
            f"attempt {i} must report the real exit code 3, got {att.get('container')!r}"
        )
    assert len({(a.get("container") or {}).get("taskArn") for a in rattempts}) == 2, (
        "each retry must be a distinct ECS task, so the two attempts must have distinct taskArns"
    )

    exited = _wait_job_status(bat, exited_id, {"SUCCEEDED", "FAILED"}, timeout_s=2 * _JOB_TERMINAL_S)
    streams.extend(_collect_log_streams(exited))
    assert exited["status"] == "FAILED", f"exit 3 must end FAILED, got {exited['status']!r}"
    eattempts = exited.get("attempts") or []
    assert len(eattempts) == 1, (
        f"onExitCode 3 -> EXIT must stop after the first attempt even though attempts=2, got "
        f"{len(eattempts)} attempts (an emulator that retries blindly records 2)"
    )


def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    from botocore.exceptions import ClientError

    retry_deadline = time.monotonic() + timeout_s
    while True:
        if not [ce for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
                if ce.get("status") != "DELETED"]:
            return
        try:
            batch.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as e:  # still UPDATING, or a job queue being deleted still references it
            if e.response["Error"]["Code"] != "ClientException" or time.monotonic() >= retry_deadline:
                raise
            time.sleep(interval_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
