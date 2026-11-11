"""job-dependency-releases-on-success-and-blocks-on-parent-failure."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-dependency-releases-on-success-and-blocks-on-parent-failure"
GROUP = 'data-plane'
SERVICES = ['batch']

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
# Bounded deadlines, each with its reason; a wait never stands in for an assertion.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> VALID -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
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
    """Detach the managed policy then delete an IAM role (best-effort)."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create this run's ECS task execution role for Fargate Batch jobs; returns its ARN.

    The role is named per run and deleted by this check's cleanup, so no pre-existing or
    shared role is ever adopted.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    return arn


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _owned_vpc_networking(ctx):
    """(subnet_ids, security_group_id) for a MANAGED Fargate CE, from networking this check owns."""
    subnet_id, sg_id = _owned_network(ctx)
    return [subnet_id], sg_id


def _owned_network(ctx) -> tuple[str, str]:
    """(subnet_id, security_group_id) in an internet-routable VPC this check creates and tears down.

    The check owns its networking: a VPC, one public subnet, an internet gateway with a default
    route (so a Fargate task can pull a public image), and the VPC's own default security group.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.182.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-batch-vpc-")}])
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.182.1.0/24", AvailabilityZone=az)["Subnet"][
        "SubnetId"
    ]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_id, sg_id


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Retry a network delete while Fargate/Batch ENIs drain (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound") or code in ("Gateway.NotAttached",):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


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


def _delete_while_in_use(delete, describe):
    """Run a Batch delete, retrying its ClientException every 2 s while the resource still exists
    (a reference that is still being released) to the teardown deadline; raise everything else."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException":
                raise
            if describe() is None:
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_jq(bat, name):
    """DISABLE -> poll VALID -> DeleteJobQueue -> poll gone.

    Skipping either poll is what leaks: DeleteJobQueue on an ENABLED queue is a 400, and
    DeleteComputeEnvironment on a still-referenced CE is a 400, so the CE would survive.
    """
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=3)
    _delete_while_in_use(lambda: bat.delete_job_queue(jobQueue=name), lambda: _describe_jq(bat, name))
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
    _delete_while_in_use(
        lambda: bat.delete_compute_environment(computeEnvironment=name), lambda: _describe_ce(bat, name)
    )
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
    subnets, sg = _owned_vpc_networking(ctx)
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    service_role_arn = _service_linked_role_arn(ctx)
    # Bounded retry, not a fixed pre-sleep: a freshly (re)created service-linked role can be
    # rejected by CreateComputeEnvironment until it propagates. Retry the call itself so a
    # target that is ready immediately pays nothing.
    resp = None
    last_err = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            resp = bat.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="MANAGED",
                state="ENABLED",
                serviceRole=service_role_arn,
                computeResources={
                    "type": "FARGATE",
                    "maxvCpus": max_vcpus,
                    "subnets": subnets,
                    "securityGroupIds": [sg],
                },
                tags=_MANAGED_TAGS,
            )
            break
        except Exception as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"could not create compute environment {ce_name}: {last_err}")
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

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """dependsOn holds a job in PENDING and releases it once the parent SUCCEEDS, while a dependent
    whose parent FAILS reaches a terminal state with no attempts and no startedAt."""
    bat = ctx.client("batch")
    streams = _log_stream_sink(ctx)
    queue, _ce_arn = _fargate_stack(ctx, bat, max_vcpus=8)
    ok_name, _a, ok_rev = _register_fargate_jd(ctx, bat, ["/bin/sh", "-c", "sleep 20; exit 0"])
    bad_name, _b, bad_rev = _register_fargate_jd(ctx, bat, ["/bin/sh", "-c", "sleep 20; exit 9"])

    # Both legs are submitted up front so they run concurrently inside one deadline.
    good_parent = _tracked_submit(ctx, bat, queue, f"{ok_name}:{ok_rev}")
    good_child = _tracked_submit(ctx, bat, queue, f"{ok_name}:{ok_rev}",
                                 dependsOn=[{"jobId": good_parent}])
    bad_parent = _tracked_submit(ctx, bat, queue, f"{bad_name}:{bad_rev}")
    bad_child = _tracked_submit(ctx, bat, queue, f"{ok_name}:{ok_rev}",
                                dependsOn=[{"jobId": bad_parent}])

    # Both children must be held while their parents are still non-terminal.
    for child_id, parent_id in ((good_child, good_parent), (bad_child, bad_parent)):
        held = _poll_until(
            lambda child_id=child_id: _describe_job(bat, child_id),
            lambda j: j is not None and j.get("status") != "SUBMITTED",
            timeout_s=_JQ_VALID_S,
            interval_s=3,
            description=f"dependent job {child_id} leaves SUBMITTED",
        )
        assert held["status"] == "PENDING", (
            f"a job with an unsatisfied dependsOn must be held in PENDING, got {held['status']!r}"
        )
        assert [d["jobId"] for d in held.get("dependsOn") or []] == [parent_id], (
            f"dependsOn must echo the parent jobId, got {held.get('dependsOn')!r}"
        )
        assert "startedAt" not in held, (
            f"a PENDING dependent has not run, so startedAt must be absent: {held.get('startedAt')}"
        )

    # Positive edge: parent succeeds -> dependent is released and runs to SUCCEEDED.
    gp_trace, gp = _trace_job_to_terminal(bat, good_parent)
    _assert_monotonic(gp_trace)
    streams.extend(_collect_log_streams(gp))
    assert gp["status"] == "SUCCEEDED", f"parent must SUCCEED, got {gp['status']!r}"
    gc_trace, gc = _trace_job_to_terminal(bat, good_child)
    _assert_monotonic(gc_trace)
    streams.extend(_collect_log_streams(gc))
    assert gc["status"] == "SUCCEEDED", (
        f"a dependent released by a SUCCEEDED parent must run to SUCCEEDED, got {gc['status']!r} "
        f"reason={gc.get('statusReason')!r}"
    )
    assert (gc.get("container") or {}).get("exitCode") == 0, (
        f"the released dependent really ran, so exitCode must be 0, got "
        f"{(gc.get('container') or {}).get('exitCode')!r}"
    )
    assert isinstance(gc.get("startedAt"), int) and gc["startedAt"] >= gp["stoppedAt"], (
        f"the dependent must not start before its parent stopped: child startedAt="
        f"{gc.get('startedAt')} parent stoppedAt={gp.get('stoppedAt')}"
    )

    # Negative edge: parent fails -> dependent must never be dispatched.
    bp_trace, bp = _trace_job_to_terminal(bat, bad_parent)
    _assert_monotonic(bp_trace)
    streams.extend(_collect_log_streams(bp))
    assert bp["status"] == "FAILED", f"parent exiting 9 must FAIL, got {bp['status']!r}"
    bc_trace, bc = _trace_job_to_terminal(bat, bad_child)
    _assert_monotonic(bc_trace)
    assert bc["status"] == "FAILED", (
        f"a dependent of a FAILED parent must not succeed; got {bc['status']!r}"
    )
    assert not (bc.get("attempts") or []), (
        f"the blocked dependent must never have been dispatched, but it recorded "
        f"{len(bc.get('attempts') or [])} attempt(s): {bc.get('attempts')!r}"
    )
    assert "startedAt" not in bc, (
        f"the blocked dependent must never have started: startedAt={bc.get('startedAt')}"
    )
    assert (bc.get("container") or {}).get("exitCode") is None, (
        f"the blocked dependent ran no container, so it must report no exitCode, got "
        f"{(bc.get('container') or {}).get('exitCode')!r}"
    )
    assert (bc.get("statusReason") or ""), "a dependency-failed job must explain itself in statusReason"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
