"""elbv2-target-group-registers-ecs-service-tasks."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "elbv2-target-group-registers-ecs-service-tasks"
GROUP = "target-registration"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Creating an ECS service with a loadBalancers target group ARN auto-registers the
    running Fargate task's ENI private IP as an ALB target (matching container port)."""
    net = _create_network(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_task_def(ctx)
    alb = _create_alb_and_tg(ctx, net["vpc_id"], net["subnet_ids"], net["sg_id"])
    service = _create_service(
        ctx, cluster, task_def_arn, net["subnet_ids"], net["sg_id"],
        tg_arn=alb["tg_arn"], desired_count=1,
    )

    _wait_running_count(ctx, cluster, service, 1, timeout_s=360)
    ips = _task_private_ips(ctx, cluster, service)
    assert len(ips) == 1, f"expected exactly one running task ENI, got {ips!r}"

    targets = _wait_target_count(ctx, alb["tg_arn"], 1, timeout_s=180)
    assert targets[0]["Target"]["Id"] == ips[0], (
        f"ALB target id {targets[0]['Target']['Id']!r} does not match the task's "
        f"ENI private IP {ips[0]!r}"
    )
    assert targets[0]["Target"]["Port"] == 80


# ===== helpers =====

def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float = 120.0, interval_s: float = 5.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _tag_spec(ctx, resource_type: str, kind: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")}]}


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec(ctx, "internet-gateway", "igw")]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.99.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "route-table", "rt")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"), Description="sim2real ecs-elbv2 test sg", VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_task_def(ctx, container_name: str = "app", container_port: int = 80) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-td-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": container_name,
            "image": "busybox:1.36",
            "command": ["sh", "-c", "mkdir -p /www && echo OK > /www/index.html && httpd -f -p 80 -h /www"],
            "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
            "essential": True,
            "healthCheck": {
                "command": ["CMD-SHELL", "wget -q -O- http://localhost:80/ | grep -q OK || exit 1"],
                "interval": 15, "timeout": 5, "retries": 3, "startPeriod": 10,
            },
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_alb_and_tg(ctx, vpc_id: str, subnet_ids: list, sg_id: str, port: int = 80) -> dict:
    elbv2 = ctx.client("elbv2")
    alb_name = ctx.unique_name("sim2real-alb-")[:32].strip("-")
    alb_arn = elbv2.create_load_balancer(
        Name=alb_name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application", Scheme="internet-facing",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))

    tg_name = ctx.unique_name("sim2real-tg-")[:32].strip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return {"alb_arn": alb_arn, "tg_arn": tg_arn, "listener_arn": listener_arn}


def _delete_service_and_wait(ecs, cluster, service) -> None:
    """Force-delete the service and wait until its tasks stop, so DeleteCluster and the target
    group and security group deletes after it find nothing still running."""
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=service)["taskArns"]
    ecs.delete_service(cluster=cluster, service=service, force=True)
    if task_arns:
        ecs.get_waiter("tasks_stopped").wait(
            cluster=cluster, tasks=task_arns, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )


def _create_service(ctx, cluster: str, task_def_arn: str, subnet_ids: list, sg_id: str, *,
                     tg_arn: "str | None" = None, container_name: str = "app",
                     container_port: int = 80, desired_count: int = 1) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    kwargs: dict[str, Any] = dict(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
    )
    if tg_arn:
        kwargs["loadBalancers"] = [{
            "targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port,
        }]
        kwargs["healthCheckGracePeriodSeconds"] = 120
    ecs.create_service(**kwargs)
    ctx.on_cleanup(lambda: _delete_service_and_wait(ecs, cluster, name))
    return name


def _wait_running_count(ctx, cluster: str, service: str, count: int, timeout_s: float = 360.0):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda rc: rc == count, timeout_s=timeout_s, interval_s=2,
                        description=f"service {service} runningCount=={count}")


def _task_private_ips(ctx, cluster: str, service: str) -> list:
    ecs = ctx.client("ecs")
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING")["taskArns"]
    if not task_arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]
    ips = []
    for t in tasks:
        for att in t.get("attachments", []):
            for det in att.get("details", []):
                if det["name"] == "privateIPv4Address":
                    ips.append(det["value"])
    return ips


def _wait_target_count(ctx, tg_arn: str, count: int, timeout_s: float = 180.0):
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]

    return _poll_until(probe, lambda ths: len(ths) == count, timeout_s=timeout_s, interval_s=2,
                        description=f"target group {tg_arn} target count=={count}")


# Network deletes wait (bounded) for the ENIs of asynchronously deleted resources (load balancers,
# tasks, clusters) to leave, retrying DependencyViolation in one window shared by all of a check's
# network deletes and sized to the cleanup budget; then they raise, naming the ENIs still attached.
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
        _time.sleep(10)
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
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


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
