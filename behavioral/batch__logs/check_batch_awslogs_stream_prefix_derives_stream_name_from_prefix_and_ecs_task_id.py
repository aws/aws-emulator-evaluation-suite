"""batch-awslogs-stream-prefix-derives-stream-name-from-prefix-and-ecs-task-id."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-awslogs-stream-prefix-derives-stream-name-from-prefix-and-ecs-task-id"
GROUP = "data-plane"
SERVICES = ["batch", "logs"]

# ===== helpers =====

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
# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> settle -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run, ONE attempt


def _swallow(fn):
    """Run a teardown step fn(); return when the resource is already gone, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidNetworkInterfaceID.NotFound", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _delete_while_in_use(fn, timeout_s=60.0):
    """Run a Batch delete, retrying every 2 s while Batch refuses it for a dependency still
    draining (ClientException); not-found returns, anything else or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _swallow(fn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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


def _fargate_execution_role_arn(ctx):
    """Create this run's own ECS task execution role for Fargate Batch jobs; returns its ARN.

    A fresh name per run, so no role the account already holds is adopted and no concurrent
    check's teardown can delete the role this check's tasks pull under.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_FARGATE_EXEC_ROLE_PREFIX)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    _wait_role_assumable(ctx, name)
    return arn


def _wait_role_assumable(ctx, role_name):
    """Bounded wait for a freshly-minted role to be readable by IAM's own read path.

    Reason: IAM create is eventually consistent and Batch/ECS reject a role it cannot yet
    resolve. Polling GetRole is the only condition observable from here, so the wait is
    bounded and raises rather than sleeping blind.
    """
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=60,
        interval_s=3,
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


def _networking(ctx):
    """(subnet_ids, security_group_id) for a Fargate CE, from a VPC this check creates.

    No account default VPC is read: the check's outcome depends only on the network it built.
    The security group is the default group of that created VPC.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _create_vpc(ctx, ec2)
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get(
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
    return subnet_ids[:3], sgs[0]["GroupId"]


def _create_vpc(ctx, ec2):
    """Create a minimal internet-routable VPC + one public subnet. Returns the VPC id."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.181.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.181.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _swallow(
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


def _wait_job_terminal(bat, job_id, timeout_s):
    """Wait for SUCCEEDED or FAILED. The terminal set excludes every transient state."""
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=10,
        description=f"job {job_id} reached SUCCEEDED or FAILED",
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue cannot be deleted while it holds non-terminal jobs and a CE cannot be deleted
    while a queue references it, so this MUST complete before the queue teardown runs.
    Registered before the queue so ctx's reverse order runs it first.
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
    _delete_while_in_use(lambda: bat.delete_job_queue(jobQueue=name))
    _swallow(
        lambda: _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _delete_while_in_use(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _swallow(
        lambda: _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    )


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE CE + ENABLED queue, both polled to VALID. Returns the queue name.

    FARGATE, never EC2: a MANAGED/EC2 CE with minvCpus > 0 keeps instances alive and is the
    classic Batch cost leak. FARGATE has no minvCpus floor, so an idle CE bills nothing even
    if teardown is truncated; maxvCpus only caps concurrency.
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
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"})
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
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name


_CONTAINER_SEGMENT = "default"  # the container name Batch gives a single-container job
_LOG_SETTLE_S = 300             # awslogs flushes on its own cadence after the container exits


def _log_group(ctx):
    """A customer-owned log group for this check's job. Returns the group name."""
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real/behav/batch-stream-naming-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _register_logging_jd(ctx, bat, *, group, prefix, sentinel, exec_role_arn):
    """A FARGATE job definition that echoes `sentinel` and logs to `group` under `prefix`."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["/bin/sh", "-c", f"echo {sentinel}"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": group,
                    "awslogs-region": ctx.region,
                    "awslogs-stream-prefix": prefix,
                },
            },
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"


def _all_streams(ctx, group):
    """Every stream name in `group`, paginated. Empty is a legitimate answer here."""
    logs = ctx.client("logs")
    names = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "limit": 50}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        names.extend(s["logStreamName"] for s in page.get("logStreams", []))
        token = page.get("nextToken")
        if not token:
            return names


def _stream_messages(ctx, group, stream):
    """Every message in one stream, oldest first. Raises if the stream does not exist."""
    logs = ctx.client("logs")
    out = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = logs.get_log_events(**kwargs)
        events = page.get("events", [])
        out.extend(e["message"] for e in events)
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return out
        token = nxt


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The CloudWatch Logs stream a Batch job writes to is named exactly
    `<awslogs-stream-prefix>/default/<ecs-task-id>`, with the task id from the taskArn DescribeJobs
    reports, and that stream, and only that stream, holds the container's output."""
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    group = _log_group(ctx)
    prefix = ctx.unique_name("sim2real-pfx-")
    sentinel = f"SIM2REAL-STREAM-NAMING-{uuid.uuid4().hex}"

    # Created before the compute environment, so IAM has the CE's provisioning time to make the
    # role assumable by ECS before any task references it.
    exec_role_arn = _fargate_execution_role_arn(ctx)
    queue = _fargate_stack(ctx, bat)
    job_def = _register_logging_jd(
        ctx, bat, group=group, prefix=prefix, sentinel=sentinel, exec_role_arn=exec_role_arn
    )
    job_id = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=queue, jobDefinition=job_def
    )["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [job_id]))

    job = _wait_job_terminal(bat, job_id, timeout_s=_JOB_TERMINAL_S)
    assert job["status"] == "SUCCEEDED", (
        f"the job must SUCCEED so its logs are a complete record, got {job['status']!r} "
        f"(statusReason={job.get('statusReason')!r})"
    )
    attempts = job["attempts"]
    assert len(attempts) == 1, (
        f"one un-retried job must record exactly 1 attempt, got {len(attempts)}: {attempts!r}"
    )
    container = attempts[0]["container"]

    # --- derive the expected stream name from two independently-read values --------------------
    task_arn = container["taskArn"]
    assert task_arn.startswith("arn:") and "/" in task_arn, (
        f"the attempt must name the real ECS task it ran as, got taskArn={task_arn!r}"
    )
    task_id = task_arn.rsplit("/", 1)[-1]
    assert task_id and task_id != task_arn, (
        f"could not parse an ECS task id out of {task_arn!r}; the derivation rule cannot be "
        f"evaluated without it"
    )
    derived = f"{prefix}/{_CONTAINER_SEGMENT}/{task_id}"

    # --- point 1: Batch's own claim about the stream name -------------------------------------
    reported = container["logStreamName"]
    assert reported == derived, (
        f"the awslogs stream name must be <prefix>/{_CONTAINER_SEGMENT}/<ecs-task-id>; derived "
        f"{derived!r} from prefix {prefix!r} and taskArn {task_arn!r}, but DescribeJobs reports "
        f"{reported!r}"
    )

    # --- point 2: the CONSUMER holds exactly that one stream, and no other --------------------
    streams = _poll_until(
        lambda: _all_streams(ctx, group),
        lambda names: bool(names),
        timeout_s=_LOG_SETTLE_S,
        interval_s=5,
        description=(
            f"CloudWatch Logs group {group} shows a stream for the finished job (awslogs flushes "
            f"on its own cadence after the container exits)"
        ),
    )
    assert streams == [derived], (
        f"the customer-owned group {group!r} received exactly one job, so it must hold exactly "
        f"one stream named {derived!r}; DescribeLogStreams reports {sorted(streams)}"
    )

    # --- point 3: the bytes under that name are THIS container's -----------------------------
    messages = _poll_until(
        lambda: _stream_messages(ctx, group, derived),
        lambda msgs: any(sentinel in m for m in msgs),
        timeout_s=_LOG_SETTLE_S,
        interval_s=5,
        description=f"the sentinel line reaches stream {derived!r}",
    )
    hits = [m for m in messages if sentinel in m]
    assert len(hits) == 1, (
        f"the container echoed the sentinel exactly once, so stream {derived!r} must carry it "
        f"exactly once; found {len(hits)} of {len(messages)} lines: {messages[:5]}"
    )
    assert hits[0].strip() == sentinel, (
        f"the sentinel line must be the container's stdout verbatim; expected {sentinel!r}, got "
        f"{hits[0]!r}"
    )

    # A second, unrelated read at the destination: the stream must be reachable by its exact
    # name through the prefix-filtered lookup too, so the name is not merely the one entry in a
    # list this check happened to enumerate.
    by_prefix = ctx.client("logs").describe_log_streams(
        logGroupName=group, logStreamNamePrefix=derived
    )["logStreams"]
    assert [s["logStreamName"] for s in by_prefix] == [derived], (
        f"DescribeLogStreams(logStreamNamePrefix={derived!r}) must resolve to exactly that "
        f"stream, got {[s.get('logStreamName') for s in by_prefix]}"
    )
    # NOT storedBytes: CloudWatch Logs stopped populating it for log streams on 2019-06-17 and
    # always reports zero, so asserting on it would fail a correct target. lastEventTimestamp is
    # the field that carries real information here.
    assert isinstance(by_prefix[0].get("lastEventTimestamp"), int), (
        f"the stream must report the timestamp of the event it holds, got "
        f"lastEventTimestamp={by_prefix[0].get('lastEventTimestamp')!r}"
    )


# EC2 network teardown: AWS-managed ENIs (here Fargate task ENIs) leave the subnet and security
# group asynchronously, so a delete waits for them and retries DependencyViolation within one window
# shared by all of the check's network deletes, then raises naming the ENIs still attached.
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
