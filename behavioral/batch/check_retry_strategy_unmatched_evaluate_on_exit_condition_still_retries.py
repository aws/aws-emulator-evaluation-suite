"""retry-strategy-unmatched-evaluate-on-exit-condition-still-retries."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-strategy-unmatched-evaluate-on-exit-condition-still-retries"
GROUP = "data-plane"
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
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> settle -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run, ONE attempt


def _swallow(fn):
    """Run a teardown step; a not-found answer counts as done and every other error raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _unless_gone(fn):
    """Run a network teardown step; only the resource's own not-found counts as done."""
    try:
        fn()
    except ClientError as exc:
        if not exc.response.get("Error", {}).get("Code", "").endswith(".NotFound"):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result); RAISE on deadline miss, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _fargate_execution_role_arn(ctx):
    """Create a per-run ECS task execution role for Fargate Batch jobs; return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-batch-exec-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    _wait_role_assumable(ctx, name)
    return arn


def _wait_role_assumable(ctx, role_name):
    """Wait until a new role is readable; IAM is eventually consistent and Batch rejects it before."""
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=_budget_s(ctx, 60),
        ctx=ctx,
        interval_s=1,
        description=f"IAM role {role_name} readable after create",
    )


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (required by a MANAGED CE). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:  # noqa: BLE001 - absent SLR is the create branch
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc
    _wait_role_assumable(ctx, "AWSServiceRoleForBatch")
    return resp["Role"]["Arn"]


_VPC_CACHE: dict = {}


def _networking(ctx):
    """(subnet_ids, security_group_id) for a Fargate CE; uses ctx.network() or creates a VPC."""
    held = _VPC_CACHE.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
    else:
        vpc_id = _create_vpc(ctx, ec2)
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", []
    )
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    assert subnet_ids, f"VPC {vpc_id} has no subnet with free addresses; cannot place a Fargate task"
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    assert sgs, f"VPC {vpc_id} has no default security group; cannot place a Fargate task"
    _VPC_CACHE[id(ctx)] = (ctx, (subnet_ids[:3], sgs[0]["GroupId"]))
    ctx.on_cleanup(lambda: _VPC_CACHE.pop(id(ctx), None))
    return _VPC_CACHE[id(ctx)][1]


def _create_vpc(ctx, ec2):
    """Create a minimal internet-routable VPC + one public subnet. Returns the VPC id."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.181.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=_budget_s(ctx, 600),
        ctx=ctx,
        interval_s=1,
        description=f"VPC {vpc_id} available",
    )
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.181.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    return vpc_id


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


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=1, ctx=None):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
        ctx=ctx,
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=1, ctx=None):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
        ctx=ctx,
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_job_terminal(bat, job_id, timeout_s, ctx=None):
    """Wait for the job to reach SUCCEEDED or FAILED."""
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=2,
        description=f"job {job_id} reached SUCCEEDED or FAILED",
        ctx=ctx,
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue holding non-terminal jobs cannot be deleted, so this must run before queue teardown.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _swallow(
            lambda jid=jid: _poll_until(
                lambda: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
                timeout_s=_TEARDOWN_S,
                interval_s=5,
                description=f"job {jid} terminal before queue teardown",
            )
        )


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    last = None
    for _ in range(15):
        try:
            bat.delete_job_queue(jobQueue=name)
            break
        except Exception as exc:  # noqa: BLE001 - a queue still draining rejects the delete
            if _describe_jq(bat, name) is None:
                return
            last = exc
            time.sleep(2)
    else:
        raise RuntimeError(f"job queue {name} was not deleted: {last!r}")
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
    _swallow(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    last = None
    for _ in range(15):
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except Exception as exc:  # noqa: BLE001 - a still-referenced CE rejects the delete
            if _describe_ce(bat, name) is None:
                return
            last = exc
            time.sleep(2)
    else:
        raise RuntimeError(f"compute environment {name} was not deleted: {last!r}")
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"compute environment {name} gone",
    )


def _delete_log_streams(ctx, stream_names):
    """Delete only this check's streams; the /aws/batch/job group is shared by every Batch job."""
    if not stream_names:
        return
    logs = ctx.client("logs")
    for s in sorted(set(stream_names)):
        _swallow(
            lambda s=s: logs.delete_log_stream(
                logGroupName="/aws/batch/job", logStreamName=s
            )
        )


def _job_streams(job):
    """Every logStreamName this job's attempts reported (empty if it never reached RUNNING)."""
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
    """MANAGED/FARGATE CE + ENABLED queue, both polled to VALID. Returns the queue name.

    Fargate has no minvCpus floor, so an idle CE bills nothing.
    """
    subnets, sg = _networking(ctx)
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
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce_arn = resp["computeEnvironmentArn"]
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _CE_VALID_S),
                  ctx=ctx)
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} must reach VALID, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )

    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _JQ_VALID_S),
                  ctx=ctx)
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name


def _register_jd(ctx, bat, command, *, retry_strategy, execution_role_arn):
    """Register one FARGATE job definition. Returns "name:revision"."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": command,
            "executionRoleArn": execution_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
        },
        retryStrategy=retry_strategy,
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"


def _submit(ctx, bat, queue, job_def, **kwargs):
    """SubmitJob with teardown registered at submit time. Returns the jobId."""
    resp = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=queue,
        jobDefinition=job_def,
        **kwargs,
    )
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


_ATTEMPTS = 3  # > 2 so "retry to attempts" and "no match means stop" give different counts
# Submissions of both legs before ECS failing to assume the new execution role is a failure.
_ROLE_ROUNDS = 3


def _role_not_assumable(job) -> bool:
    """The job failed before any attempt because ECS could not yet assume its execution role."""
    return (
        job["status"] == "FAILED"
        and not job.get("attempts")
        and (job.get("statusReason") or "").startswith("ECS was unable to assume the role")
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An evaluateOnExit list that matches no attempt still retries to `attempts` (3 distinct
    tasks, each exit code 3), while a matching EXIT rule stops after 1 attempt; one job definition.

    Reference: https://docs.aws.amazon.com/batch/latest/userguide/job_retries.html
    """
    bat = ctx.client("batch")
    streams: list = []
    ctx.on_cleanup(lambda: _delete_log_streams(ctx, streams))

    # The execution role is created first, so IAM propagates it while the CE comes up.
    execution_role_arn = _fargate_execution_role_arn(ctx)
    queue = _fargate_stack(ctx, bat)
    job_def = _register_jd(
        ctx,
        bat,
        ["/bin/sh", "-c", "exit 3"],
        retry_strategy={
            "attempts": _ATTEMPTS,
            "evaluateOnExit": [{"onExitCode": "7", "action": "EXIT"}],
        },
        execution_role_arn=execution_role_arn,
    )

    # Both legs are submitted up front so their attempts overlap inside one deadline. maxvCpus=4
    # against 0.25 vCPU per task means neither leg queues behind the other. ECS may not yet be
    # able to assume the new execution role; such a job fails before its first attempt, so both
    # legs are submitted again, a bounded number of times.
    for _ in range(_ROLE_ROUNDS):
        unmatched_id = _submit(
            ctx, bat, queue, job_def,
            containerOverrides={"command": ["/bin/sh", "-c", "exit 3"]},
        )
        matched_id = _submit(
            ctx, bat, queue, job_def,
            containerOverrides={"command": ["/bin/sh", "-c", "exit 7"]},
        )

        # Leg 1 runs 3 sequential Fargate attempts, so 3x the single-attempt budget.
        unmatched = _wait_job_terminal(
            bat, unmatched_id, timeout_s=_budget_s(ctx, _ATTEMPTS * _JOB_TERMINAL_S), ctx=ctx
        )
        matched = _wait_job_terminal(
            bat, matched_id, timeout_s=_budget_s(ctx, _ATTEMPTS * _JOB_TERMINAL_S), ctx=ctx
        )
        if not (_role_not_assumable(unmatched) or _role_not_assumable(matched)):
            break

    # --- leg 1: no rule matches exit code 3, so the job must be retried to `attempts` ---------
    streams.extend(_job_streams(unmatched))
    assert unmatched["status"] == "FAILED", (
        f"a job whose every attempt exits 3 must end FAILED, got {unmatched['status']!r} "
        f"(statusReason={unmatched.get('statusReason')!r})"
    )
    u_attempts = unmatched["attempts"]
    assert len(u_attempts) == _ATTEMPTS, (
        f"evaluateOnExit matched no attempt, so the documented default (retry) must run "
        f"exactly {_ATTEMPTS} attempts; DescribeJobs reports {len(u_attempts)} "
        f"(statusReason={unmatched.get('statusReason')!r}). "
        f"1 means retryStrategy was ignored or an unmatched condition was treated as EXIT"
    )
    for i, att in enumerate(u_attempts):
        code = (att.get("container") or {}).get("exitCode")
        assert code == 3, (
            f"attempt {i} of the unmatched leg must report the container's real exit code 3, "
            f"got {code!r} from container={att.get('container')!r}"
        )
    task_arns = {(a.get("container") or {}).get("taskArn") for a in u_attempts}
    assert None not in task_arns and len(task_arns) == _ATTEMPTS, (
        f"each retry is a fresh ECS task, so {_ATTEMPTS} attempts must carry {_ATTEMPTS} "
        f"distinct non-null taskArns, got {sorted(str(t) for t in task_arns)}"
    )

    # --- leg 2: the SAME rule list matches exit code 7 with EXIT, so exactly 1 attempt --------
    streams.extend(_job_streams(matched))
    assert matched["status"] == "FAILED", (
        f"a job whose only attempt exits 7 must end FAILED, got {matched['status']!r} "
        f"(statusReason={matched.get('statusReason')!r})"
    )
    m_attempts = matched["attempts"]
    assert len(m_attempts) == 1, (
        f"onExitCode 7 -> EXIT must stop after attempt 1 even though attempts={_ATTEMPTS}, got "
        f"{len(m_attempts)} attempts; {_ATTEMPTS} means the rule was not evaluated"
    )
    m_code = (m_attempts[0].get("container") or {}).get("exitCode")
    assert m_code == 7, (
        f"the matched leg's single attempt must report exit code 7, got {m_code!r}; "
        f"a wrong code here means containerOverrides.command was not honoured, which would "
        f"also invalidate leg 1's exit-3 reading"
    )


# AWS-managed ENIs are released asynchronously after their owner is deleted, so an immediate
# subnet/VPC delete fails with DependencyViolation. Wait for them within one shared bounded window,
# retry DependencyViolation, and finally raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
