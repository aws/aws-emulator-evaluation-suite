"""capprov-zero-capacity-provider-rejects-task-and-no-container-runs."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "capprov-zero-capacity-provider-rejects-task-and-no-container-runs"

GROUP = "capacity-provider"

SERVICES = ["ecs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RunTask on an ACTIVE capacity provider with zero capacity is refused, no task or log stream
    appears, and the same task runs to completion on the cluster's FARGATE provider.
    """
    ecs = ctx.client("ecs")
    net = _own_network(ctx)
    log_group = _create_log_group(ctx)
    exec_role_arn = _exec_role(ctx)
    asg_arn = _empty_asg(ctx, net)
    provider = _capacity_provider(ctx, asg_arn)
    cluster = _create_cluster(ctx, [provider, "FARGATE"])

    marker = ctx.unique_name("capprov-ran-")
    td_arn = _register_task_def(ctx, log_group, exec_role_arn, marker)
    _ensure_ecs_slr(ctx)

    described = _describe_provider(ctx, provider)
    # Re-read as ACTIVE so the refusal below is attributable to capacity, not provider state.
    assert described.get("status") == "ACTIVE", (
        f"the capacity provider must be ACTIVE for the refusal below to be about capacity rather "
        f"than about provider state; it is {described.get('status')!r}: {described!r}"
    )
    cluster_before = ecs.describe_clusters(clusters=[cluster])["clusters"][0]
    assert cluster_before.get("registeredContainerInstancesCount") == 0, (
        f"the Auto Scaling group behind {provider!r} was created with zero capacity, so the "
        f"cluster must have no registered container instances: {cluster_before!r}"
    )

    # Break exactly one thing: the provider the strategy names has nowhere to put the task.
    # Everything else -- cluster, task definition, subnet, security group -- is what the control
    # below uses successfully.
    err = _error_of(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            count=1,
            capacityProviderStrategy=[{"capacityProvider": provider, "weight": 1}],
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["security_groups"],
                }
            },
        )
    )
    assert err["code"] == "InvalidParameterException", (
        f"RunTask onto a capacity provider with no capacity must be refused "
        f"InvalidParameterException, got {err!r}"
    )
    assert err["message"] == (
        f"The specified capacity provider '{provider}' contains no container instances."
    ), (
        f"the refusal must name the capacity provider and say it contains no container "
        f"instances, got {err['message']!r}"
    )

    # The effect is absent: not a task in any desired status, and not a single log stream, so no
    # container was started and none was even attempted.
    refused_tasks = _all_task_arns(ecs, cluster)
    assert refused_tasks == [], (
        f"the refused RunTask must leave no task behind on the cluster; found {refused_tasks!r}"
    )
    streams_after_refusal = _stream_names(ctx, log_group)
    assert streams_after_refusal == [], (
        f"no container may have started, so the log group this check created must hold no stream; "
        f"found {streams_after_refusal!r}"
    )

    # Positive control, same cluster, same task definition, same subnet: the OTHER provider of
    # this cluster places the task and its container really runs.
    task_arn = _run_control_task(ctx, cluster, td_arn, net)
    control = _await_task(ecs, cluster, task_arn, {"STOPPED"}, timeout_s=270.0)
    assert control.get("capacityProviderName") == "FARGATE", (
        f"the control task should report the provider it was placed on: {control!r}"
    )
    container = (control.get("containers") or [{}])[0]
    assert container.get("exitCode") == 0, (
        f"the control container did not exit 0, so this file proves nothing about the refusal "
        f"above: container={container!r} stoppedReason={control.get('stoppedReason')!r}"
    )

    stream = f"{_STREAM_PREFIX}/{_CONTAINER_NAME}/{task_arn.rsplit('/', 1)[-1]}"
    messages = _await_messages(ctx, log_group, stream, marker)
    blob = "\n".join(messages)
    assert marker in blob, (
        f"the control container never printed its marker {marker!r}; its stream held {messages!r}"
    )
    assert task_arn in blob, (
        f"the control stream does not carry the control task's own ARN {task_arn!r} as read back "
        f"from its metadata endpoint, so its output cannot be attributed to it: {messages!r}"
    )

    # And the refused task still has not appeared: exactly one task ever existed on this cluster.
    final_tasks = _all_task_arns(ecs, cluster)
    assert final_tasks == [task_arn], (
        f"the cluster must hold exactly the one control task -- the refused RunTask must never "
        f"have materialised one; found {final_tasks!r}"
    )
    final_streams = _stream_names(ctx, log_group)
    assert final_streams == [stream], (
        f"exactly one container ran, so exactly one log stream may exist; found {final_streams!r}"
    )


# ECR Public busybox: a tiny multi-arch image an anonymous Fargate pull can always fetch, so a
# check about the scheduler is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_PREFIX = "sim2real-capprov-"
_STREAM_PREFIX = "capprov"
_CONTAINER_NAME = "app"
_INSTANCE_TYPE = "t3.micro"
# The AWS-published ECS-optimized AMI parameter: a launch template needs an image id, and this is
# read from AWS rather than pinned so the check does not carry a region-local literal. The Auto
# Scaling group below never launches an instance (min=max=desired=0), which is the point.
_ECS_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
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
    """Delete something whose dependencies (a Fargate ENI, a capacity provider still attached to a
    cluster that is deleting) clear asynchronously.
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


def _error_of(fn) -> dict:
    """The error code and message of a call that MUST fail; a success raises rather than
    returning a sentinel that would read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return {
            "code": err.response["Error"]["Code"],
            "message": err.response["Error"].get("Message", ""),
        }
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _own_network(ctx) -> dict:
    """A VPC, public subnet, internet gateway and security group of this check's own (an account
    may have no default VPC). The AZ is one that is available AND offers the instance type."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available availability zone in {ctx.region} offers {_INSTANCE_TYPE}; offerings were "
        f"{sorted(offered)!r}"
    )

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.78.1.0/24",
        AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    )
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_kv()}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=assoc))
    )

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(_PREFIX + "sg-"),
        Description="sim2real capacity-provider check egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))
    return {"vpc_id": vpc_id, "subnets": [subnet_id], "security_groups": [sg_id]}


def _empty_asg(ctx, net: dict) -> str:
    """An Auto Scaling group that can never launch anything: min=max=desired=0, tagged at creation."""
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    image_id = ctx.client("ssm").get_parameter(Name=_ECS_AMI_PARAM)["Parameter"]["Value"]
    lt_name = ctx.unique_name(_PREFIX + "lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": _INSTANCE_TYPE},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    )

    asg_name = ctx.unique_name(_PREFIX + "asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=net["subnets"][0],
        Tags=[
            {"Key": k, "Value": v, "PropagateAtLaunch": False} for k, v in _MANAGED_TAGS.items()
        ],
    )
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: autoscaling.delete_auto_scaling_group(
                AutoScalingGroupName=asg_name, ForceDelete=True
            )
        )
    )
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["Instances"] == [], (
        f"the Auto Scaling group behind the capacity provider must hold no instance: {group!r}"
    )
    return group["AutoScalingGroupARN"]


def _capacity_provider(ctx, asg_arn: str) -> str:
    """An EC2 capacity provider with managed scaling DISABLED, so ECS must answer with the capacity
    it has (none) instead of scaling the group out."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_PREFIX + "cp-")
    ecs.create_capacity_provider(
        name=name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=_ecs_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ecs.delete_capacity_provider(capacityProvider=name))
    )
    return name


def _describe_provider(ctx, name: str) -> dict:
    """The provider's own record, PAGINATED and filtered to the one this check created."""
    ecs = ctx.client("ecs")
    token = None
    while True:
        kwargs: dict = {"capacityProviders": [name]}
        if token:
            kwargs["nextToken"] = token
        page = ecs.describe_capacity_providers(**kwargs)
        for provider in page.get("capacityProviders", []):
            if provider.get("name") == name:
                return provider
        token = page.get("nextToken")
        if not token:
            raise AssertionError(f"capacity provider {name!r} is not describable after creation")


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _teardown_call(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _exec_role(ctx) -> str:
    """A task execution role with exactly the awslogs permissions the container's driver needs.
    IAM is eventually consistent, so the policy is polled back and the control RunTask retries."""
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
    """A cluster with the capacity providers associated, polled to ACTIVE: until then RunTask
    fails ClusterNotFoundException ('The referenced cluster is not active')."""
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
    """One task definition usable by BOTH providers of the cluster, so the refusal below cannot be
    a task-definition compatibility difference. Its container prints a marker and then its own
    identity, read from the task metadata endpoint ECS injects."""
    ecs = ctx.client("ecs")
    arn = ecs.register_task_definition(
        family=ctx.unique_name(_PREFIX + "td-"),
        requiresCompatibilities=["EC2", "FARGATE"],
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
    )["taskDefinition"]["taskDefinitionArn"]

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


def _run_control_task(ctx, cluster: str, td_arn: str, net: dict) -> str:
    """The positive control: the cluster's OTHER capacity provider places the task.
    A not-yet-assumable execution role and momentary Fargate unavailability are retried, bounded."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    kwargs = dict(
        cluster=cluster,
        taskDefinition=td_arn,
        count=1,
        capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
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
        assert not failures, f"the control RunTask on FARGATE reported failures: {failures!r}"
        return resp["tasks"][0]["taskArn"]
    raise AssertionError(f"the control RunTask never placed a task; last obstacle was {last!r}")


def _all_task_arns(ecs, cluster: str) -> list[str]:
    """Every task on this check's own cluster in EITHER desired status, PAGINATED."""
    arns: list[str] = []
    for desired in ("RUNNING", "STOPPED"):
        paginator = ecs.get_paginator("list_tasks")
        for page in paginator.paginate(cluster=cluster, desiredStatus=desired):
            arns += page.get("taskArns", [])
    return sorted(set(arns))


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


def _stream_names(ctx, group: str) -> list[str]:
    """Every stream in the group, PAGINATED -- an emptiness assertion is only sound if a later
    page cannot hide one."""
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
            return sorted(names)


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


# AWS-managed ENIs of resources deleted asynchronously keep a subnet/SG/VPC delete failing with
# DependencyViolation for a while, so teardown waits (bounded) for them and retries.
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
