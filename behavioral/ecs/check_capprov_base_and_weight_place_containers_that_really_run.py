"""capprov-base-and-weight-place-containers-that-really-run."""

from __future__ import annotations

import json
import time
from collections import Counter

from behavioral_harness import tags

CHECK = "capprov-base-and-weight-place-containers-that-really-run"

GROUP = "capacity-provider"

SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask(count=3) with base=1 on FARGATE_SPOT and all weight on FARGATE places tasks 1/2, and
    each task's container exits 0 and logs a marker plus its own task ARN from task metadata.
    """
    ecs = ctx.client("ecs")
    net = _own_network(ctx, want_zones=2)
    log_group = _create_log_group(ctx)
    exec_role_arn = _exec_role(ctx)
    cluster = _create_cluster(ctx, ["FARGATE", "FARGATE_SPOT"])

    marker = ctx.unique_name("capprov-ran-")
    td_arn = _register_task_def(ctx, log_group, exec_role_arn, marker)

    # base=1 on FARGATE_SPOT guarantees the first task there; weight=0 means it gets no share of
    # anything beyond the base, so both remaining tasks must land on FARGATE (the only provider
    # with a non-zero weight). The split of count=3 is therefore fully determined: 1 + 2.
    strategy = [
        {"capacityProvider": "FARGATE_SPOT", "base": 1, "weight": 0},
        {"capacityProvider": "FARGATE", "base": 0, "weight": 1},
    ]
    tasks = _run_tasks(ctx, cluster, td_arn, net, count=3, strategy=strategy)
    task_arns = [t["taskArn"] for t in tasks]

    assert len(tasks) == 3, f"expected RunTask(count=3) to place 3 tasks, got {len(tasks)}: {tasks!r}"
    placed = Counter(t.get("capacityProviderName") for t in tasks)
    assert placed == Counter({"FARGATE": 2, "FARGATE_SPOT": 1}), (
        f"base=1 on FARGATE_SPOT plus all weight on FARGATE must split 3 tasks 1/2; RunTask "
        f"reported {dict(placed)!r}"
    )

    # RunTask's own response is the mutating call; re-read the placement independently.
    described = _describe_tasks(ecs, cluster, task_arns)
    assert len(described) == 3, f"DescribeTasks returned {len(described)} of 3 tasks: {described!r}"
    described_placement = {t["taskArn"]: t.get("capacityProviderName") for t in described}
    assert Counter(described_placement.values()) == Counter({"FARGATE": 2, "FARGATE_SPOT": 1}), (
        f"an independent DescribeTasks read disagrees with the RunTask placement: "
        f"{described_placement!r}"
    )

    # Each container must have run to completion and logged its own task identity.
    stopped = {
        arn: _await_task(ecs, cluster, arn, {"STOPPED"}, timeout_s=270.0) for arn in task_arns
    }
    for arn, task in stopped.items():
        container = (task.get("containers") or [{}])[0]
        assert container.get("exitCode") == 0, (
            f"the container of the task placed on {described_placement[arn]!r} did not exit 0: "
            f"container={container!r} stoppedReason={task.get('stoppedReason')!r} "
            f"stopCode={task.get('stopCode')!r}"
        )

    streams = _stream_names(ctx, log_group)
    assert len(streams) == 3, (
        f"the log group this check created should hold exactly one stream per placed task; "
        f"found {len(streams)}: {sorted(streams)!r}"
    )

    for arn in task_arns:
        stream = f"{_STREAM_PREFIX}/{_CONTAINER_NAME}/{arn.rsplit('/', 1)[-1]}"
        assert stream in streams, (
            f"no log stream {stream!r} for the task placed on {described_placement[arn]!r}, so "
            f"nothing proves its container ran; streams were {sorted(streams)!r}"
        )
        messages = _await_messages(ctx, log_group, stream, marker)
        blob = "\n".join(messages)
        assert marker in blob, (
            f"the container of the task placed on {described_placement[arn]!r} never printed its "
            f"marker {marker!r}; its stream held {messages!r}"
        )
        # The container read its own identity from the task metadata endpoint, so this binds the
        # output to THAT task rather than to the stream-naming convention.
        assert arn in blob, (
            f"the stream for the task placed on {described_placement[arn]!r} does not contain that "
            f"task's own ARN {arn!r} as read back from its metadata endpoint, so the output cannot "
            f"be attributed to it; stream held {messages!r}"
        )

    spot_arn = next(a for a, p in described_placement.items() if p == "FARGATE_SPOT")
    fargate_arns = sorted(a for a, p in described_placement.items() if p == "FARGATE")
    assert len(fargate_arns) == 2, f"expected two FARGATE tasks, got {fargate_arns!r}"
    spot_blob = "\n".join(_log_messages(ctx, log_group, _stream_for(spot_arn)))
    assert not any(a in spot_blob for a in fargate_arns), (
        f"the FARGATE_SPOT task's stream also carries a FARGATE task's ARN, so the two providers' "
        f"containers cannot be told apart: {spot_blob[:600]!r}"
    )


# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the scheduler is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_PREFIX = "sim2real-capprov-"
_STREAM_PREFIX = "capprov"
_CONTAINER_NAME = "app"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-capprov"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


# Codes a teardown call returns when the resource is already gone, and codes AWS returns while a
# dependency (a Fargate ENI, a stopping task, an attached capacity provider) is still released.
_GONE_CODES = (
    "NoSuchEntity",
    "ResourceNotFoundException",
    "ClusterNotFoundException",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound",
    "InvalidGroup.NotFound",
    "Gateway.NotAttached",
    "InvalidLaunchTemplateName.NotFoundException",
)
_IN_USE_CODES = (
    "DependencyViolation",
    "ResourceInUse",
    "ResourceInUseException",
    "ScalingActivityInProgress",
    "ClusterContainsTasksException",
    "ClusterContainsServicesException",
    "ClusterContainsContainerInstancesException",
    "UpdateInProgressException",
)


def _teardown_call(fn) -> None:
    """A teardown call: an already-gone resource is fine, any other failure raises."""
    _retry_delete(fn, timeout_s=0.0)


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _retry_delete(fn, *, timeout_s: float = 120.0) -> None:
    """Delete something whose dependencies (a Fargate ENI, a stopping task) clear asynchronously.
    In-use codes retry every 2 s to the deadline; an already-gone resource is fine; the rest raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _GONE_CODES:
                return
            if code not in _IN_USE_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _own_network(ctx, *, want_zones: int = 1) -> dict:
    """A VPC, public subnets, an internet gateway and a security group created by this check.

    No NAT gateway or EIP: public-IP tasks pull through the internet gateway, leaving nothing billable."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= want_zones, (
        f"{ctx.region} offers {len(zones)} available availability zones, need {want_zones}: "
        f"{zones!r}"
    )

    subnet_ids = []
    for i, zone in enumerate(zones[:want_zones]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{i + 1}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda s=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=s))
        )
        subnet_ids.append(subnet_id)

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    )
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_kv()}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for subnet_id in subnet_ids:
        assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(
            lambda a=assoc: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=a))
        )

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(_PREFIX + "sg-"),
        Description="sim2real capacity-provider check egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    return {"vpc_id": vpc_id, "subnets": subnet_ids, "security_groups": [sg_id]}


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _teardown_call(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _exec_role(ctx) -> str:
    """A task execution role with exactly the awslogs permissions the container's driver needs.

    IAM has no "role is assumable" signal, so RunTask retries 'unable to assume the role'."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + "exec-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop() -> None:
        _teardown_call(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _teardown_call(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    _poll_until(
        lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
        description=f"role {name} inline policy readable",
    )
    return arn


def _create_cluster(ctx, capacity_providers: list[str]) -> str:
    """A cluster with the named capacity providers, polled until ACTIVE with attachments settled:
    until then RunTask fails ClusterNotFoundException ('The referenced cluster is not active')."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_PREFIX + "cluster-")
    ecs.create_cluster(
        clusterName=name, capacityProviders=capacity_providers, tags=_ecs_tags_kv()
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=name)))
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[name], include=["ATTACHMENTS"])["clusters"][0],
        lambda c: c.get("status") == "ACTIVE"
        and c.get("attachmentsStatus") in (None, "UPDATE_COMPLETE"),
        timeout_s=180,
        interval_s=5,
        description=f"cluster {name} ACTIVE with its capacity providers attached",
    )
    return name


def _register_task_def(ctx, log_group: str, exec_role_arn: str, marker: str) -> str:
    """One task definition whose container prints a marker and then its own identity, read from
    the task metadata endpoint ECS injects. wget's exit status is the container's, so a metadata
    endpoint that is absent surfaces as a non-zero exitCode rather than as a silent pass."""
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name(_PREFIX + "td-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": _CONTAINER_NAME,
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": [
                    "sh",
                    "-c",
                    f'echo "{marker}"; wget -qO- "$ECS_CONTAINER_METADATA_URI_V4/task"',
                ],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": _STREAM_PREFIX,
                    },
                },
            }
        ],
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]

    def _drop() -> None:
        ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")

    ctx.on_cleanup(_drop)
    return arn


def _ensure_ecs_slr(ctx) -> None:
    """RunTask on Fargate needs AWSServiceRoleForECS (CreateService auto-creates it, RunTask does
    not). Idempotent -- already-exists is success, and the role is never deleted."""
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _run_tasks(ctx, cluster: str, td_arn: str, net: dict, *, count: int, strategy: list) -> list:
    """RunTask with a capacity provider strategy, tolerating two conditions that are not the
    subject: a freshly created execution role ECS cannot assume yet, and Fargate Spot capacity
    being momentarily unavailable in the region. Both are retried, bounded; neither is asserted."""
    from botocore.exceptions import ClientError

    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    kwargs = dict(
        cluster=cluster,
        taskDefinition=td_arn,
        count=count,
        capacityProviderStrategy=strategy,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClientException" and "ssume" in str(err).lower():
                last = err
                time.sleep(5)
                continue
            raise
        for task in resp.get("tasks", []):
            arn = task["taskArn"]
            ctx.on_cleanup(
                lambda a=arn: _teardown_call(
                    lambda: ecs.stop_task(cluster=cluster, task=a, reason="sim2real-cleanup")
                )
            )
        failures = resp.get("failures") or []
        if failures and all("apacity is unavailable" in str(f.get("reason", "")) for f in failures):
            last = failures
            time.sleep(2)
            continue
        assert not failures, f"RunTask reported failures placing {count} tasks: {failures!r}"
        return resp["tasks"]
    raise AssertionError(f"RunTask never placed {count} tasks; last obstacle was {last!r}")


def _describe_tasks(ecs, cluster: str, task_arns: list[str]) -> list:
    return ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]


def _await_task(ecs, cluster: str, task_arn: str, statuses: set, *, timeout_s=270.0) -> dict:
    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(
        probe,
        lambda t: t.get("lastStatus") in statuses,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"task {task_arn} lastStatus in {sorted(statuses)}",
    )


def _stream_for(task_arn: str) -> str:
    return f"{_STREAM_PREFIX}/{_CONTAINER_NAME}/{task_arn.rsplit('/', 1)[-1]}"


def _stream_names(ctx, group: str) -> list[str]:
    """Every stream in the group, PAGINATED -- the count assertion is only sound if a later page
    cannot hide one."""
    logs = ctx.client("logs")
    names: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        names += [s["logStreamName"] for s in page.get("logStreams", [])]
        token = page.get("nextToken")
        if not token:
            return names


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, PAGINATED forward from the head."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = _safe(lambda: logs.get_log_events(**kwargs))
        if page is None:
            return msgs
        events = page.get("events", [])
        msgs += [e.get("message", "") for e in events]
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return msgs
        token = nxt


def _await_messages(ctx, group: str, stream: str, marker: str) -> list[str]:
    """awslogs delivery trails the container's exit, so poll for the marker rather than reading
    once and concluding the container printed nothing."""
    return _poll_until(
        lambda: _log_messages(ctx, group, stream),
        lambda ms: any(marker in m for m in ms),
        timeout_s=180,
        interval_s=5,
        description=f"marker {marker!r} in log stream {stream}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
