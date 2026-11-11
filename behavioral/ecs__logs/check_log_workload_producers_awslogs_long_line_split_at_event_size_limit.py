"""log-workload-producers-awslogs-long-line-split-at-event-size-limit."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-workload-producers-awslogs-long-line-split-at-event-size-limit"

GROUP = "container-logs-delivery"

SERVICES = ["ecs", "logs"]

# PutLogEvents accounts each event as its UTF-8 message bytes plus 26 bytes of overhead,
# against a 256 KiB (262144-byte) event cap, so the largest message the awslogs driver
# can put in ONE event is 262144 - 26 bytes.
_MAX_EVENT_MESSAGE = 262144 - 26


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """awslogs delivers a line of up to 262118 bytes (256 KiB less the 26-byte event overhead) as
    one event, and splits a longer one losslessly into consecutive events led by a 262118-byte
    chunk, none larger; how the remainder is chunked is not asserted."""
    tag = ctx.unique_name("ll-")
    sizes = [40000, _MAX_EVENT_MESSAGE, _MAX_EVENT_MESSAGE + 1, 300000]
    lines = {}
    parts = []
    for n in sizes:
        head = f"L{n}-{tag}:"
        lines[n] = head + ("0123456789" * (n // 10 + 1))[: n - len(head)]
        assert len(lines[n].encode()) == n
        # busybox awk: double a seed string past n, then cut; writes one line of exactly n bytes.
        parts.append(
            f"awk -v n={n} -v h={head} 'BEGIN{{s=\"0123456789\"; while(length(s)<n) s=s s; "
            f"print h substr(s,1,n-length(h))}}'"
        )
    end = f"{tag}-END"
    parts.append(f"echo {end}")

    net = _network(ctx)
    group = _log_group(ctx)
    role = _exec_role(ctx, ["logs:CreateLogStream", "logs:PutLogEvents"])
    cluster = _cluster(ctx)
    prefix = ctx.unique_name("long-")
    td = _task_def(ctx, [{
        "name": "app", "image": _PUBLIC_IMAGE, "essential": True,
        "command": ["sh", "-c", "; ".join(parts)],
        "logConfiguration": _awslogs(group, ctx.region, prefix),
    }], role)
    (task,) = _run_started(ctx, cluster, [td], net)
    c = task["containers"][0]
    assert c.get("exitCode") == 0, (
        f"container did not exit 0: exitCode={c.get('exitCode')!r} reason={task.get('stoppedReason')!r}"
    )

    stream = f"{prefix}/app/{task['taskArn'].rsplit('/', 1)[-1]}"
    events = _poll_until(
        lambda: _events(ctx, group, stream) if stream in _streams(ctx, group, prefix + "/") else [],
        lambda ev: bool(ev) and ev[-1]["message"] == end,
        timeout_s=300,
        description=f"end marker as the last event of {stream}",
    )
    msgs = [e["message"].encode("utf-8") for e in events]
    assert all(len(m) <= _MAX_EVENT_MESSAGE for m in msgs), (
        f"an event exceeds {_MAX_EVENT_MESSAGE} bytes: {[len(m) for m in msgs]!r}"
    )

    # Reassemble in stream order: each expected line consumes consecutive events.
    i = 0
    chunks = {}
    for n in sizes:
        want = lines[n].encode()
        got = b""
        chunks[n] = []
        while len(got) < len(want):
            assert i < len(msgs), f"ran out of events reassembling the {n}-byte line"
            got += msgs[i]
            chunks[n].append(len(msgs[i]))
            i += 1
        assert got == want, (
            f"{n}-byte line reassembled to {len(got)} bytes; first mismatch at "
            f"{next((k for k, (a, b) in enumerate(zip(got, want)) if a != b), min(len(got), len(want)))}"
        )
    assert msgs[i:] == [end.encode()], f"unexpected trailing events: {[m[:40] for m in msgs[i:]]!r}"

    assert chunks[40000] == [40000], f"40000-byte line split as {chunks[40000]!r}"
    assert chunks[_MAX_EVENT_MESSAGE] == [_MAX_EVENT_MESSAGE], (
        f"max-size line split as {chunks[_MAX_EVENT_MESSAGE]!r}"
    )
    assert chunks[_MAX_EVENT_MESSAGE + 1] == [_MAX_EVENT_MESSAGE, 1], (
        f"max+1 line split as {chunks[_MAX_EVENT_MESSAGE + 1]!r}, expected [262118, 1]"
    )
    assert len(chunks[300000]) >= 2 and chunks[300000][0] == _MAX_EVENT_MESSAGE, (
        f"300000-byte line split as {chunks[300000]!r}"
    )


# ===== helpers =====
# Own VPC (never the ambient default VPC): one VPC, an internet gateway, a public route
# table and two subnets in derived AZs. assignPublicIp=ENABLED lets Fargate pull the
# ECR Public image through the IGW, so no NAT gateway or EIP is ever created.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _TAGS.items()]


#: Error codes saying the resource does not exist: already deleted, or not created yet.
_GONE = ("ClusterNotFoundException", "ResourceNotFoundException", "NoSuchEntity",
         "Gateway.NotAttached")
#: Error codes of a delete refused while a dependency (a stopping task) is released.
_IN_USE = ("ClusterContainsTasksException", "ClusterContainsServicesException",
           "ResourceInUseException")
_RELEASE_S = 120.0


def _unless_gone(fn, retry_s: float = 0.0):
    """fn(), or None when the target answers that the resource does not exist; within retry_s an
    in-use refusal is retried every 2 s; every other error raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in _GONE:
                return None
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _network(ctx):
    """(subnet_ids, sg_id) in a VPC this check creates and tears down."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_PREFIX + "vpc-")

    def spec(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, *_tags_kv()]}]

    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"]
    made = {"vpc": vpc, "subnets": [], "igw": None, "rtb": None, "sg": None}

    def _drop():
        # Fargate releases a task's ENI asynchronously after STOPPED; wait for that to
        # happen (an observable condition) before the subnets can be deleted.
        _poll_until(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}]
            )["NetworkInterfaces"],
            lambda enis: not enis, timeout_s=420, interval_s=2,
            description=f"the task ENIs in {vpc} released",
        )
        for sn in made["subnets"]:
            _unless_gone(lambda sn=sn: ec2.delete_subnet(SubnetId=sn))
        if made["rtb"]:
            _unless_gone(lambda: ec2.delete_route_table(RouteTableId=made["rtb"]))
        if made["igw"]:
            _unless_gone(lambda: ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc))
            _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=made["igw"]))
        if made["sg"]:
            _unless_gone(lambda: ec2.delete_security_group(GroupId=made["sg"]))
        _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc))

    ctx.on_cleanup(_drop)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway"))
    made["igw"] = igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc)
    made["rtb"] = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table"))[
        "RouteTable"
    ]["RouteTableId"]
    ec2.create_route(
        RouteTableId=made["rtb"], DestinationCidrBlock="0.0.0.0/0", GatewayId=made["igw"]
    )
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"need two available AZs in {ctx.region}, found {azs!r}"
    for i, az in enumerate(azs[:2]):
        sn = ec2.create_subnet(
            VpcId=vpc, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=spec("subnet"),
        )["Subnet"]["SubnetId"]
        made["subnets"].append(sn)
        ec2.associate_route_table(RouteTableId=made["rtb"], SubnetId=sn)
    made["sg"] = ec2.create_security_group(
        GroupName=name, Description="sim2real ecs log producer egress", VpcId=vpc,
        TagSpecifications=spec("security-group"),
    )["GroupId"]
    return list(made["subnets"]), made["sg"]


def _exec_role(ctx, actions):
    """Task execution role trusting ecs-tasks with ONE inline logs policy; returns ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + "exec-")[:64]
    arn = iam.create_role(
        RoleName=name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"))
        _unless_gone(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name, PolicyName="logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}),
    )
    # IAM exposes no "policy is effective" condition: _run_task retries a not-yet-assumable
    # role and _run_started reruns a task that failed to start on it.
    return arn


def _log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_PREFIX + "cl-")
    ecs.create_cluster(clusterName=name, tags=[{"key": k, "value": v} for k, v in _TAGS.items()])

    # Tasks still stopping block the delete for a while: retried while in use.
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_cluster(cluster=name), _RELEASE_S))
    return name


def _awslogs(group, region, prefix, **extra):
    opts = {"awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": prefix}
    opts.update(extra)
    return {"logDriver": "awslogs", "options": opts}


def _task_def(ctx, containers, exec_role=None):
    ecs = ctx.client("ecs")
    kw = dict(
        family=ctx.unique_name(_PREFIX + "td-"),
        containerDefinitions=containers,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu="256", memory="512",
    )
    if exec_role:
        kw["executionRoleArn"] = exec_role
    arn = ecs.register_task_definition(**kw)["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _ensure_ecs_slr(ctx):
    """Fargate RunTask needs AWSServiceRoleForECS; creating it is idempotent (exists = ok)."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # InvalidInput: the account already holds the role
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _run_task(ctx, cluster, td_arn, net, overrides=None, timeout_s=120):
    """RunTask, retrying only while a just-created execution role is not yet assumable."""
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    subnets, sg = net
    kw = dict(
        cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnets, "securityGroups": [sg], "assignPublicIp": "ENABLED"}},
    )
    if overrides:
        kw["overrides"] = overrides
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = ecs.run_task(**kw)
        except ClientError as err:
            msg = err.response.get("Error", {}).get("Message", "")
            if "unable to assume the role" not in msg.lower() or time.monotonic() > deadline:
                raise
            time.sleep(5)
            continue
        if resp.get("tasks"):
            arn = resp["tasks"][0]["taskArn"]
            ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.stop_task(cluster=cluster, task=arn)))
            return arn
        assert time.monotonic() < deadline, f"RunTask never placed a task: {resp.get('failures')!r}"
        time.sleep(5)


#: Bound for a fresh execution role's grant to reach the ECS agent.
_IAM_PROPAGATION_S = 120.0


def _role_not_yet_usable(task):
    """A start failure from the execution role not yet usable: unassumable or a grant denied."""
    reason = task.get("stoppedReason") or ""
    return task.get("stopCode") == "TaskFailedToStart" and (
        "unable to assume" in reason.lower() or "is not authorized to perform" in reason)


def _run_started(ctx, cluster, td_arns, net, timeout_s=600):
    """Run one task per definition to STOPPED, relaunching any that failed to start on the fresh
    execution role for up to _IAM_PROPAGATION_S; returns the stopped tasks in order."""
    left = ctx.time_left()
    deadline = time.monotonic() + (
        _IAM_PROPAGATION_S if left is None else min(_IAM_PROPAGATION_S, left))
    arns = [_run_task(ctx, cluster, td, net) for td in td_arns]
    tasks = [_await_stopped(ctx, cluster, a, timeout_s=timeout_s) for a in arns]
    while any(_role_not_yet_usable(t) for t in tasks) and time.monotonic() < deadline:
        time.sleep(2)
        tasks = [_await_stopped(ctx, cluster, _run_task(ctx, cluster, td, net), timeout_s=timeout_s)
                 if _role_not_yet_usable(t) else t for t, td in zip(tasks, td_arns)]
    return tasks


def _await_stopped(ctx, cluster, task_arn, timeout_s=600):
    ecs = ctx.client("ecs")

    def probe():
        ts = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return ts[0] if ts else {}

    return _poll_until(probe, lambda t: t.get("lastStatus") == "STOPPED", timeout_s=timeout_s,
                       description=f"task {task_arn} STOPPED")


def _streams(ctx, group, prefix=None):
    logs = ctx.client("logs")
    kw = {"logGroupName": group}
    if prefix:
        kw["logStreamNamePrefix"] = prefix
    out = []
    for page in logs.get_paginator("describe_log_streams").paginate(**kw):
        out.extend(s["logStreamName"] for s in page["logStreams"])
    return sorted(out)


def _events(ctx, group, stream):
    """Every event in the stream, oldest first, following nextForwardToken to the end."""
    logs = ctx.client("logs")
    out, token = [], None
    while True:
        kw = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kw["nextToken"] = token
        r = logs.get_log_events(**kw)
        out.extend(r["events"])
        if r.get("nextForwardToken") == token:
            return out
        token = r.get("nextForwardToken")


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
