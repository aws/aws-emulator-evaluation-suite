"""elbv2-target-group-deregistration-delay-respected-positive."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "elbv2-target-group-deregistration-delay-respected-positive"
GROUP = "connection-draining"
SERVICES = ["cloudformation", "ecs", "elbv2"]


# timing:real-time — lease: 30 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#deregistration-delay
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A deregistering target stays 'draining' for roughly the configured delay before disappearing."""
    net = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    td_arn = _register_task_def(
        ctx, exec_role_arn, "web", "public.ecr.aws/docker/library/httpd:latest", 80
    )
    alb = _create_alb(ctx, net["subnet_ids"], net["sg_id"])
    delay_s = 30
    tg_arn = _create_target_group(ctx, net["vpc_id"], deregistration_delay=delay_s)
    _create_listener(ctx, alb["arn"], tg_arn)
    svc = _create_service(
        ctx,
        cluster_arn,
        td_arn,
        net["subnet_ids"],
        net["sg_id"],
        desired_count=1,
        tg_arn=tg_arn,
        container_name="web",
        container_port=80,
    )
    _wait_service_stable(ctx, cluster_arn, svc["name"])

    task_arns = _list_running_task_arns(ctx, cluster_arn, svc["name"])
    assert len(task_arns) == 1, (
        f"expected exactly 1 running task, got {len(task_arns)}: {task_arns}"
    )
    task_arn = task_arns[0]
    ip = _task_private_ip(ctx, cluster_arn, task_arn)

    _poll_until(
        lambda: _find_target(ctx, tg_arn, ip)["TargetHealth"]["State"],
        lambda s: s == "healthy",
        timeout_s=90,
        interval_s=5,
    )

    ecs = ctx.client("ecs")
    ecs.stop_task(
        cluster=cluster_arn,
        task=task_arn,
        reason="sim2real-behav deregistration delay test",
    )

    # How long ECS takes to actually call DeregisterTargets after stop_task (container
    # stop period, ENI/agent state propagation) is its own latency, unrelated to the
    # configured deregistration delay -- it can exceed delay_s itself, so this poll gets
    # a generous, delay-INDEPENDENT budget. The
    # delay's own effect is measured below, rooted at when draining first appears.
    draining = _poll_until(
        lambda: _find_target(ctx, tg_arn, ip),
        lambda d: d is not None and d["TargetHealth"]["State"] == "draining",
        timeout_s=180,
        interval_s=3,
    )
    assert draining is not None, "target never entered draining after stop_task"
    assert draining["TargetHealth"]["State"] == "draining", (
        f"expected State=draining after stop_task, got {draining['TargetHealth']['State']!r}"
    )
    assert draining["TargetHealth"]["Reason"] == "Target.DeregistrationInProgress", (
        "expected Reason=Target.DeregistrationInProgress while draining, got "
        f"{draining['TargetHealth'].get('Reason')!r}"
    )
    draining_since = time.monotonic()

    # Sanity: still draining right after we observed it -- not already gone.
    still_present = _find_target(ctx, tg_arn, ip)
    assert (
        still_present is not None
        and still_present["TargetHealth"]["State"] == "draining"
    ), (
        f"expected the target to still be draining immediately after observing it so, got {still_present!r}"
    )

    # The delay is "respected" only if the target survives a meaningful fraction of
    # it before disappearing, and disappears once it (plus buffer) elapses.
    gone = _poll_until(
        lambda: _find_target(ctx, tg_arn, ip),
        lambda d: d is None,
        timeout_s=delay_s + 60,
        interval_s=5,
    )
    assert gone is None, (
        f"expected target fully deregistered after the delay, still present: {gone}"
    )
    elapsed_draining = time.monotonic() - draining_since
    assert elapsed_draining >= delay_s * 0.5, (
        f"target disappeared only {elapsed_draining:.1f}s after entering draining, expected at "
        f"least half of the configured {delay_s}s delay -- the delay may not be honored"
    )


def _find_target(ctx, tg_arn, ip):
    for d in _target_health(ctx, tg_arn):
        if d["Target"]["Id"] == ip:
            return d
    return None


# ===== helpers =====
_PREFIX = "sim2real-ecsalb-"


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": "behavioral"}]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": "sim2real", "value": "behavioral"}]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _owned_vpc(ctx, ec2, "10.183.0.0/24")
    sg_id = ec2.create_security_group(
        GroupName=_name(ctx, "sg"),
        Description="sim2real ecs-alb shared sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 0,
                "ToPort": 65535,
                "IpRanges": [{"CidrIp": "10.183.0.0/24"}],
            }
        ],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = _name(ctx, "exec-role")
    trust = json.dumps(
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
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    # IAM role propagation lag is absorbed by _wait_service_stable's bounded waiter below:
    # ECS keeps retrying task launches (which assume this role) until the service reaches
    # steady state or its own deadline expires, so no separate fixed sleep is needed here.
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
    arn = ecs.create_cluster(
        clusterName=_name(ctx, "cluster"),
        tags=_ecs_tags_kv(),
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, arn))
    return arn


def _register_task_def(
    ctx, exec_role_arn, container_name, image, container_port, command=None
):
    ecs = ctx.client("ecs")
    container = {
        "name": container_name,
        "image": image,
        "essential": True,
        "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=_name(ctx, "taskdef"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
        tags=_ecs_tags_kv(),
    )
    td_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_def(ecs, td_arn))
    return td_arn


def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise RuntimeError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_load_balancer(
        Name=_name(ctx, "alb"),
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=_tags_kv(),
    )
    alb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    alb_dns = resp["LoadBalancers"][0]["DNSName"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])[
            "LoadBalancers"
        ][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=240,
        interval_s=10,
    )
    return {"arn": alb_arn, "dns": alb_dns}


def _create_target_group(
    ctx,
    vpc_id,
    port=80,
    target_type="ip",
    health_check_path="/",
    interval=10,
    healthy_threshold=2,
    unhealthy_threshold=2,
    deregistration_delay=None,
):
    elbv2 = ctx.client("elbv2")
    timeout = max(2, min(interval - 1, 5))
    tg_arn = elbv2.create_target_group(
        Name=_name(ctx, "tg"),
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType=target_type,
        HealthCheckProtocol="HTTP",
        HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval,
        HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold,
        UnhealthyThresholdCount=unhealthy_threshold,
        Tags=_tags_kv(),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    if deregistration_delay is not None:
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_arn,
            Attributes=[
                {
                    "Key": "deregistration_delay.timeout_seconds",
                    "Value": str(deregistration_delay),
                }
            ],
        )
    return tg_arn


def _create_listener(ctx, alb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_service(
    ctx,
    cluster_arn,
    task_def_arn,
    subnet_ids,
    sg_id,
    desired_count=1,
    tg_arn=None,
    container_name=None,
    container_port=None,
    grace_period=None,
):
    ecs = ctx.client("ecs")
    name = _name(ctx, "svc")
    kwargs = dict(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=_ecs_tags_kv(),
    )
    if tg_arn:
        kwargs["loadBalancers"] = [
            {
                "targetGroupArn": tg_arn,
                "containerName": container_name,
                "containerPort": container_port,
            }
        ]
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


def _wait_service_stable(ctx, cluster_arn, service_name, timeout_s=420):
    ecs = ctx.client("ecs")
    waiter = ecs.get_waiter("services_stable")
    waiter.wait(
        cluster=cluster_arn,
        services=[service_name],
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, timeout_s // 2)},
    )


def _list_running_task_arns(ctx, cluster_arn, service_name):
    ecs = ctx.client("ecs")
    return ecs.list_tasks(
        cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING"
    )["taskArns"]


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]


def _task_private_ip(ctx, cluster_arn, task_arn):
    ecs = ctx.client("ecs")
    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for d in att.get("details", []):
                if d["name"] == "privateIPv4Address":
                    return d["value"]
    raise AssertionError(f"no ENI private IP found for task {task_arn}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
