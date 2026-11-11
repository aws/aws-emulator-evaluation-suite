"""elbv2-security-group-mismatch-blocks-health-checks-negative."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "elbv2-security-group-mismatch-blocks-health-checks-negative"
GROUP = "network-boundary"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task security group that does not allow the ALB's health-check traffic keeps targets unhealthy."""
    net = _create_base_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    td_arn = _register_task_def(ctx, exec_role_arn, "web", "public.ecr.aws/docker/library/httpd:latest", 80)
    alb = _create_alb(ctx, net["subnet_ids"], net["alb_sg_id"])
    tg_arn = _create_target_group(ctx, net["vpc_id"], interval=5)
    _create_listener(ctx, alb["arn"], tg_arn)

    # Effect absent: task SG has NO inbound rules at all (default new-SG behavior) -- the ALB's
    # health-check probes to port 80 are dropped, so the target must never become healthy.
    svc = _create_service(
        ctx, cluster_arn, td_arn, net["subnet_ids"], net["task_sg_id"],
        desired_count=1, tg_arn=tg_arn, container_name="web", container_port=80,
    )

    running = _poll_until(
        lambda: _list_running_task_arns(ctx, cluster_arn, svc["name"]),
        lambda arns: len(arns) == 1,
        timeout_s=90, interval_s=5,
    )
    assert len(running) == 1, f"expected exactly one running task, got {running!r}"

    # On real AWS, ECS replaces a task that keeps failing its ALB health check, so a fresh
    # replacement can be briefly co-registered next to the timed-out original -- "exactly one target" does not hold, but "no registered target is ever
    # healthy" does.
    unhealthy = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda ds: bool(ds) and any(d["TargetHealth"]["State"] == "unhealthy" for d in ds)
        and all(d["TargetHealth"]["State"] != "healthy" for d in ds),
        timeout_s=120, interval_s=5,
    )
    first_unhealthy = next(d for d in unhealthy if d["TargetHealth"]["State"] == "unhealthy")
    assert first_unhealthy["TargetHealth"]["Reason"] == "Target.Timeout", (
        f"expected reason Target.Timeout for an SG-blocked health check, got {first_unhealthy['TargetHealth']!r}"
    )

    # Absence by contrast: the target timed out under the blocked SG, and the ordered control
    # below shows opening that one ingress rule is what makes it healthy.

    # Positive control: opening ingress from the ALB security group on the health-check port
    # is the ONLY thing that changes -- and it must let the target become healthy.
    ec2 = ctx.client("ec2")
    ec2.authorize_security_group_ingress(
        GroupId=net["task_sg_id"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
            "UserIdGroupPairs": [{"GroupId": net["alb_sg_id"]}],
        }],
    )
    # Same relaxation as above: a lingering replacement-churn target from the blocked phase may
    # still be draining when ingress opens, so demand at least one healthy target rather than
    # exactly one.
    healthy = _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda ds: any(d["TargetHealth"]["State"] == "healthy" for d in ds),
        timeout_s=90, interval_s=5,
    )
    assert any(d["TargetHealth"]["State"] == "healthy" for d in healthy), (
        f"expected at least one target to become healthy once ALB-SG ingress was opened, got {healthy!r}"
    )


_PREFIX = "sim2real-ecsalb-"


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _sg_tags(name):
    return [{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}]


def _delete_when_free(fn, timeout_s=600.0, interval_s=10.0):
    """Teardown: retry a VPC-scoped delete while AWS still reports a dependency. Fargate task and
    load-balancer ENIs are released asynchronously after their owners are deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("DependencyViolation", "ResourceInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _ec2_tags(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name},
                                                      {"Key": "sim2real:managed", "Value": "true"}]}]


def _owned_vpc(ctx, ec2, cidr):
    """A VPC the check creates: two public subnets in two AZs, routed to an internet gateway."""
    import ipaddress

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_ec2_tags("vpc", _name(ctx, "vpc")))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags("internet-gateway", _name(ctx, "igw")))[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_when_free(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_ec2_tags("route-table", _name(ctx, "rtb")))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an ALB needs two availability zones; {ctx.region} offers {zones!r}"
    halves = list(ipaddress.ip_network(cidr).subnets(prefixlen_diff=1))
    subnet_ids = []
    for zone, block in zip(zones[:2], halves):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=str(block), AvailabilityZone=zone,
            TagSpecifications=_ec2_tags("subnet", _name(ctx, "subnet")))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_base_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _owned_vpc(ctx, ec2, "10.181.0.0/24")

    alb_sg_name = _name(ctx, "alb-sg")
    alb_sg_id = ec2.create_security_group(
        GroupName=alb_sg_name, Description="sim2real alb sg (no inbound rule)", VpcId=vpc_id,
        TagSpecifications=_sg_tags(alb_sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_security_group(GroupId=alb_sg_id)))

    # Deliberately no ingress rules -- health checks from the ALB SG will be dropped.
    task_sg_name = _name(ctx, "task-sg")
    task_sg_id = ec2.create_security_group(
        GroupName=task_sg_name, Description="sim2real task sg (no ingress)", VpcId=vpc_id,
        TagSpecifications=_sg_tags(task_sg_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_security_group(GroupId=task_sg_id)))

    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "alb_sg_id": alb_sg_id, "task_sg_id": task_sg_id}


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = _name(ctx, "exec-role")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # No fixed settle: the service-creation poll below (90s, 5s interval) already tolerates ECS
    # retrying task launch while the freshly attached trust/execution policy propagates.
    return role_arn


def _delete_cluster_when_empty(ecs, cluster_arn, timeout_s=600.0, interval_s=10.0):
    """Teardown: a cluster refuses deletion while its tasks are still stopping, so wait them out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(interval_s)


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = _name(ctx, "cluster")
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "Name", "value": name}])["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, arn))
    return arn


def _register_task_def(ctx, exec_role_arn, container_name, image, container_port, command=None):
    ecs = ctx.client("ecs")
    container = {
        "name": container_name,
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
    }
    if command:
        container["command"] = command
    family = _name(ctx, "taskdef")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "Name", "value": family}],
    )
    td_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    return td_arn


def _retire_task_definition(ecs, task_def_arn: str) -> None:
    """Deregister then delete a task definition revision: deregistering alone leaves it
    listed as INACTIVE, so the revision is only really gone once deleted too."""
    try:
        described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_def_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_def_arn} teardown failed: {failures}")


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = _name(ctx, "alb")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internet-facing", Type="application", IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )
    alb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    alb_dns = resp["LoadBalancers"][0]["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=240, interval_s=10,
    )
    return {"arn": alb_arn, "dns": alb_dns}


def _create_target_group(ctx, vpc_id, port=80, target_type="ip", health_check_path="/",
                          interval=10, healthy_threshold=2, unhealthy_threshold=2,
                          deregistration_delay=None):
    elbv2 = ctx.client("elbv2")
    timeout = max(2, min(interval - 1, 5))
    name = _name(ctx, "tg")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType=target_type,
        HealthCheckProtocol="HTTP", HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval, HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold, UnhealthyThresholdCount=unhealthy_threshold,
        Tags=[{"Key": "Name", "Value": name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    if deregistration_delay is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(deregistration_delay)}],
        )
    return tg_arn


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_service(ctx, cluster_arn, task_def_arn, subnet_ids, sg_id, desired_count=1,
                     tg_arn=None, container_name=None, container_port=None, grace_period=None):
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc")
    kwargs = dict(
        cluster=cluster_arn, serviceName=name, taskDefinition=task_def_arn,
        desiredCount=desired_count, launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        tags=[{"key": "Name", "value": name}],
    )
    if tg_arn:
        kwargs["loadBalancers"] = [{
            "targetGroupArn": tg_arn, "containerName": container_name, "containerPort": container_port,
        }]
    if grace_period is not None:
        kwargs["healthCheckGracePeriodSeconds"] = grace_period
    svc_arn = ecs.create_service(**kwargs)["service"]["serviceArn"]

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
        try:
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": svc_arn, "name": name}


def _list_running_task_arns(ctx, cluster_arn, service_name):
    ecs = ctx.client("ecs")
    return ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
