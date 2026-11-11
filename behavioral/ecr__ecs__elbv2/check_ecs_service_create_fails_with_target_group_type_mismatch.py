"""ecs-service-create-fails-with-target-group-type-mismatch."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-create-fails-with-target-group-type-mismatch"
GROUP = "permission-boundary"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService rejects an "instance"-type target group for an awsvpc task definition
    (awsvpc requires TargetType "ip") and creates no service, while an otherwise identical
    request against an "ip"-type target group succeeds (positive control)."""
    net = _create_network(ctx, "10.100.0.0/16")
    cluster = _create_cluster(ctx)
    task_def_arn = _register_task_def(ctx)

    tg_instance_type = _create_alb_and_tg(
        ctx, net["vpc_id"], net["subnet_ids"], net["sg_id"], target_type="instance",
    )["tg_arn"]
    ecs = ctx.client("ecs")

    code, message = _error(lambda: ecs.create_service(
        cluster=cluster,
        serviceName=ctx.unique_name("sim2real-svc-mismatch-"),
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": net["subnet_ids"], "securityGroups": [net["sg_id"]], "assignPublicIp": "ENABLED",
        }},
        loadBalancers=[{"targetGroupArn": tg_instance_type, "containerName": "app", "containerPort": 80}],
    ))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = (
        f"The provided target group {tg_instance_type} has target type instance, which is "
        "incompatible with the awsvpc network mode specified in the task definition."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no service with that name/config exists in the cluster.
    arns = ecs.list_services(cluster=cluster)["serviceArns"]
    assert arns == [], f"expected no services created after the rejected call, found {arns!r}"

    # Positive control: identical request, but the target group's TargetType is "ip"
    # (as required for awsvpc network mode) -- CreateService succeeds.
    tg_ip_type = _create_alb_and_tg(
        ctx, net["vpc_id"], net["subnet_ids"], net["sg_id"], target_type="ip",
    )["tg_arn"]
    control_name = ctx.unique_name("sim2real-svc-control-")
    ecs.create_service(
        cluster=cluster,
        serviceName=control_name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": net["subnet_ids"], "securityGroups": [net["sg_id"]], "assignPublicIp": "ENABLED",
        }},
        loadBalancers=[{"targetGroupArn": tg_ip_type, "containerName": "app", "containerPort": 80}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=control_name, force=True))
    control_arns = ecs.list_services(cluster=cluster)["serviceArns"]
    assert len(control_arns) == 1, f"expected the control service to exist, found {control_arns!r}"


# ===== helpers =====


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise AssertionError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_network(ctx, cidr: str) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    prefix = cidr.split(".")[1]
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.{prefix}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"), Description="sim2real ecs-elbv2 test sg", VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
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
        }],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, task_def_arn))
    return task_def_arn


def _create_alb_and_tg(ctx, vpc_id: str, subnet_ids: list, sg_id: str, port: int = 80,
                        target_type: str = "ip") -> dict:
    elbv2 = ctx.client("elbv2")
    alb_name = ctx.unique_name("sim2real-alb-")[:32].strip("-")
    alb_arn = elbv2.create_load_balancer(
        Name=alb_name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application", Scheme="internal",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))

    tg_name = ctx.unique_name("sim2real-tg-")[:32].strip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType=target_type,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return {"alb_arn": alb_arn, "tg_arn": tg_arn, "listener_arn": listener_arn}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
