"""ecs-service-deregisters-tasks-on-scale-down."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-service-deregisters-tasks-on-scale-down"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scaling a Fargate service to 0 deregisters its task's target from the target group only after
    holding it 'draining' for about the configured deregistration delay."""
    dereg_delay_s = 10
    poll_interval_s = 5
    stack = _provision(ctx, desired_count=1, dereg_delay_s=dereg_delay_s)

    _wait_service_running(ctx, stack["cluster_arn"], stack["service_name"], 1)

    # Establish that the target really is registered before we scale down.
    _poll_until(
        lambda: len(_target_health(ctx, stack["tg_arn"])),
        lambda n: n >= 1,
        timeout_s=180,
        interval_s=10,
        desc="task target to register before scale-down",
    )

    ecs = ctx.client("ecs")
    ecs.update_service(cluster=stack["cluster_arn"], service=stack["service_name"], desiredCount=0)

    # ECS itself takes a while (its own task-stop sequence) before it ever calls
    # DeregisterTargets, so the outer deadline has to cover that plus the drain -- the
    # thing under test is only the second span: draining-observed -> gone.
    drain_started_at: float | None = None
    removed_at: float | None = None
    last_states: list[str | None] = []
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        targets = _target_health(ctx, stack["tg_arn"])
        last_states = [t["TargetHealth"].get("State") for t in targets]
        if not targets:
            removed_at = time.monotonic()
            break
        if drain_started_at is None and "draining" in last_states:
            drain_started_at = time.monotonic()
        time.sleep(poll_interval_s)
    else:
        raise AssertionError(
            "timed out waiting for the target to be deregistered after scale-down; "
            f"last observed target states: {last_states!r}"
        )

    assert drain_started_at is not None, (
        "the target disappeared from the target group without ever being observed in "
        f"'draining' state -- deregistration_delay.timeout_seconds={dereg_delay_s} was not "
        f"honored (last observed target states: {last_states!r})"
    )
    drain_elapsed = removed_at - drain_started_at
    assert drain_elapsed >= dereg_delay_s - poll_interval_s, (
        f"target vanished {drain_elapsed:.1f}s after first entering 'draining', faster than the "
        f"configured deregistration_delay.timeout_seconds={dereg_delay_s}s allows for (poll "
        f"granularity {poll_interval_s}s)"
    )
    assert drain_elapsed <= dereg_delay_s + 120, (
        f"target stayed in 'draining' for {drain_elapsed:.1f}s, far longer than the configured "
        f"deregistration_delay.timeout_seconds={dereg_delay_s}s -- deregistration appears stuck"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed: {last!r}")


def _retry_delete(fn, *, timeout_s=300.0):
    """Retry a delete while ENIs, listeners and Fargate tasks that hold the resource drain away."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith("NotFound"):
                return
            if code not in ("DependencyViolation", "ResourceInUse") or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _create_public_vpc(ctx):
    """Create a VPC with an internet gateway and public subnets in two AZs; register cleanup."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    rtb_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if z["State"] == "available"
    ]
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.43.{i + 1}.0/24", AvailabilityZone=zone)[
            "Subnet"
        ]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(
            lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid))
        )
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ecs-elb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real ecs/elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return sg_id


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # No fixed sleep for IAM propagation: _wait_service_running's bounded retry (below)
    # already tolerates ECS retrying task launches until the role becomes assumable.
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=arn))
    return arn


def _register_task_def(ctx, execution_role_arn, container_name="web", container_port=80):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/httpd:2.4",
                "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
                "essential": True,
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_target_group(ctx, vpc_id, port=80, health_check_port=None, interval=10, dereg_delay_s=None):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    kwargs: dict[str, Any] = dict(
        Name=name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )
    if health_check_port is not None:
        kwargs["HealthCheckPort"] = str(health_check_port)
    tg_arn = elbv2.create_target_group(**kwargs)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    if dereg_delay_s is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(dereg_delay_s)}],
        )
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")
    alb_arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=300,
        interval_s=10,
        desc="ALB to become active",
    )
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["DNSName"]
    return alb_arn, dns_name


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    return listener_arn


def _create_service(ctx, cluster_arn, task_def_arn, tg_arn, subnet_ids, sg_id, container_name, container_port, desired_count=1):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
        },
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port}],
    )

    def _cleanup():
        try:
            ecs.update_service(cluster=cluster_arn, service=name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        ecs.delete_service(cluster=cluster_arn, service=name, force=True)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_service_running(ctx, cluster_arn, service_name, desired_count, timeout_s=420):
    ecs = ctx.client("ecs")

    def probe():
        d = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        return d["runningCount"]

    return _poll_until(probe, lambda n: n >= desired_count, timeout_s=timeout_s, interval_s=15, desc="ECS service running count")


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


def _provision(ctx, *, desired_count=1, container_port=80, health_check_port=None, dereg_delay_s=None):
    vpc_id, subnet_ids = _create_public_vpc(ctx)
    sg_id = _create_sg(ctx, vpc_id)
    execution_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    container_name = "web"
    task_def_arn = _register_task_def(ctx, execution_role_arn, container_name, container_port)
    tg_arn = _create_target_group(ctx, vpc_id, container_port, health_check_port, dereg_delay_s=dereg_delay_s)
    alb_arn, dns_name = _create_alb(ctx, subnet_ids, sg_id)
    _create_listener(ctx, alb_arn, tg_arn, port=80)
    service_name = _create_service(
        ctx, cluster_arn, task_def_arn, tg_arn, subnet_ids, sg_id, container_name, container_port, desired_count
    )
    return {
        "vpc_id": vpc_id,
        "subnet_ids": subnet_ids,
        "sg_id": sg_id,
        "cluster_arn": cluster_arn,
        "task_def_arn": task_def_arn,
        "tg_arn": tg_arn,
        "alb_arn": alb_arn,
        "dns_name": dns_name,
        "service_name": service_name,
        "container_name": container_name,
        "container_port": container_port,
    }


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
