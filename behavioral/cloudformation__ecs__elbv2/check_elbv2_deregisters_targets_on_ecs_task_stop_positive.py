"""elbv2-deregisters-targets-on-ecs-task-stop-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elbv2-deregisters-targets-on-ecs-task-stop-positive"
GROUP = "target-lifecycle"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """Stopping an ECS task drains, then deregisters, its ALB target (identified by ENI IP)."""
    net = _create_network(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    td_arn = _register_task_def(ctx, exec_role_arn, "web", "public.ecr.aws/docker/library/httpd:latest", 80)
    alb = _create_alb(ctx, net["subnet_ids"], net["sg_id"])
    tg_arn = _create_target_group(ctx, net["vpc_id"], deregistration_delay=20)
    _create_listener(ctx, alb["arn"], tg_arn)
    svc = _create_service(
        ctx, cluster_arn, td_arn, net["subnet_ids"], net["sg_id"],
        desired_count=2, tg_arn=tg_arn, container_name="web", container_port=80,
        grace_period=120,
    )
    _wait_service_stable(ctx, cluster_arn, svc["name"])

    task_arns = _list_running_task_arns(ctx, cluster_arn, svc["name"])
    assert len(task_arns) == 2
    victim_task = task_arns[0]
    victim_ip = _task_private_ip(ctx, cluster_arn, victim_task)

    descs = _target_health(ctx, tg_arn)
    victim_before = next(d for d in descs if d["Target"]["Id"] == victim_ip)
    assert victim_before["TargetHealth"]["State"] == "healthy"

    ecs = ctx.client("ecs")
    ecs.stop_task(cluster=cluster_arn, task=victim_task, reason="sim2real-behav test stop")

    # After stop, the target must transition away from "healthy" (draining or gone) --
    # never remain reported healthy while the task is stopping/stopped.
    def _victim_state():
        for d in _target_health(ctx, tg_arn):
            if d["Target"]["Id"] == victim_ip:
                return d["TargetHealth"]["State"]
        return None  # fully deregistered

    state = _poll_until(
        _victim_state,
        lambda s: s in ("draining", None),
        timeout_s=120, interval_s=5,
    )
    assert state in ("draining", None)

    final_state = _poll_until(
        _victim_state,
        lambda s: s is None,
        timeout_s=90, interval_s=5,
    )
    assert final_state is None, "stopped task's target was never fully deregistered"


# ===== helpers =====
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


def _managed_tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real:managed", "Value": "true"}],
    }


def _create_network(ctx):
    # The account's default VPC can carry a dangling DHCP option set (DhcpOptionsId "default" ->
    # InvalidDhcpOptionID.NotFound), which fails EVERY Fargate task at launch. A freshly created
    # VPC auto-associates a valid DHCP option set, so provision a dedicated one instead of
    # depending on the default.
    ec2 = ctx.client("ec2")
    _teardown_deadline = {}

    def _retry_delete(fn, **kwargs):
        # DeleteLoadBalancer returns before its ENIs actually detach from their subnets/SG, so the
        # network teardown below (which runs after it, LIFO) can race that detach. Shares one
        # deadline across every call here rather than a fresh one per resource, so a stuck resource
        # cannot starve the ones queued behind it within ctx.on_cleanup's 60s budget.
        _teardown_deadline.setdefault("until", time.monotonic() + 40.0)
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                transient = exc.response.get("Error", {}).get("Code") == "DependencyViolation"
                if not transient or time.monotonic() >= _teardown_deadline["until"]:
                    raise
                time.sleep(3)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16", TagSpecifications=[_managed_tag_spec("vpc", _name(ctx, "vpc"))]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete((lambda **_kw: _delete_net(ec2, "delete_vpc", **_kw)), VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_managed_tag_spec("internet-gateway", _name(ctx, "igw"))]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    # LIFO: the gateway is detached before it is deleted.
    ctx.on_cleanup(lambda: _retry_delete((lambda **_kw: _delete_net(ec2, "delete_internet_gateway", **_kw)), InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _retry_delete((lambda **_kw: _delete_net(ec2, "detach_internet_gateway", **_kw)), InternetGatewayId=igw_id, VpcId=vpc_id))

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_managed_tag_spec("subnet", _name(ctx, f"subnet{i}"))],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ctx.on_cleanup(lambda sid=sid: _retry_delete((lambda **_kw: _delete_net(ec2, "delete_subnet", **_kw)), SubnetId=sid))
        subnet_ids.append(sid)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_managed_tag_spec("route-table", _name(ctx, "rt"))]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda assoc_id=assoc_id: ec2.disassociate_route_table(AssociationId=assoc_id))

    sg_id = ec2.create_security_group(
        GroupName=_name(ctx, "sg"), Description="sim2real ecs-alb shared sg", VpcId=vpc_id,
        TagSpecifications=[_managed_tag_spec("security-group", _name(ctx, "sg-tag"))],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete((lambda **_kw: _delete_net(ec2, "delete_security_group", **_kw)), GroupId=sg_id))
    # The ALB and the tasks share this group; the self-reference admits the ALB's health checks.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = _name(ctx, "exec-role")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    # Bounded wait for the attachment to become visible before the task launch that
    # depends on assuming this role -- IAM/STS propagation lag, not a fixed delay.
    def _attached():
        return [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]

    _poll_until(_attached, lambda arns: policy_arn in arns, timeout_s=30, interval_s=2)
    return role_arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=_name(ctx, "cluster"))["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_cluster_delete(ecs, arn))
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
    resp = ecs.register_task_definition(
        family=_name(ctx, "taskdef"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[container],
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
        Name=_name(ctx, "alb"), Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internet-facing", Type="application", IpAddressType="ipv4",
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
    tg_arn = elbv2.create_target_group(
        Name=_name(ctx, "tg"), Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType=target_type,
        HealthCheckProtocol="HTTP", HealthCheckPath=health_check_path,
        HealthCheckIntervalSeconds=interval, HealthCheckTimeoutSeconds=timeout,
        HealthyThresholdCount=healthy_threshold, UnhealthyThresholdCount=unhealthy_threshold,
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
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        try:
            ecs.delete_service(cluster=cluster_arn, service=name, force=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ServiceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": svc_arn, "name": name}


def _wait_service_stable(ctx, cluster_arn, service_name, timeout_s=420):
    ecs = ctx.client("ecs")
    waiter = ecs.get_waiter("services_stable")
    waiter.wait(cluster=cluster_arn, services=[service_name],
                WaiterConfig={"Delay": 2, "MaxAttempts": max(1, timeout_s // 2)})


def _list_running_task_arns(ctx, cluster_arn, service_name):
    ecs = ctx.client("ecs")
    return ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]


def _target_health(ctx, tg_arn):
    elbv2 = ctx.client("elbv2")
    return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]


def _task_private_ip(ctx, cluster_arn, task_arn):
    ecs = ctx.client("ecs")
    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for d in att.get("details", []):
                if d["name"] == "privateIPv4Address":
                    return d["value"]
    raise AssertionError(f"no ENI private IP found for task {task_arn}")


# A load balancer, cluster or task in this VPC deletes asynchronously: its ENIs stay in the subnet /
# security group for a while, so DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with
# DependencyViolation until they leave. Wait (bounded) for the ENIs, retry DependencyViolation in the
# same window, and raise naming any ENI still attached; every other error propagates.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _retry_cluster_delete(ecs, arn, timeout_s=300.0):
    """Delete the cluster once the force-deleted service's Fargate tasks have stopped."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            held = code in ("ClusterContainsTasksException", "ClusterContainsServicesException")
            if not held or time.monotonic() > deadline:
                raise
            time.sleep(10)


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
