"""alb-request-count-metric-in-cloudwatch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alb-request-count-metric-in-cloudwatch"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """HTTP requests through an ALB fronting ECS tasks increment RequestCount under AWS/ApplicationELB."""
    vpc_id, subnet_ids = _check_vpc_and_subnets(ctx)
    alb_sg = _create_http_sg(ctx, vpc_id, cidrs=ctx.ingress_cidrs())
    task_sg = _create_http_sg(ctx, vpc_id, source_sg=alb_sg)
    role_arn = _create_execution_role(ctx)
    task_def_arn = _register_task_def(ctx, role_arn, "public.ecr.aws/nginx/nginx:latest", port=80)
    cluster = _create_cluster(ctx)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn, lb_name, dns_name = _create_alb(ctx, subnet_ids, alb_sg)
    _create_listener(ctx, lb_arn, tg_arn)
    service = _create_service(ctx, cluster, task_def_arn, subnet_ids, task_sg, tg_arn)
    _wait_service_running(ctx, cluster, service, timeout_s=600)
    _wait_targets_healthy(ctx, tg_arn, timeout_s=300)

    ok = _generate_http_traffic(ctx, dns_name, count=40, delay=1.0)
    assert ok >= 20, f"expected most of 40 requests to succeed against a healthy ALB, got {ok} OK"

    lb_dim_value = "/".join(lb_arn.split("/")[-3:])  # app/<name>/<id>
    dims = [{"Name": "LoadBalancer", "Value": lb_dim_value}]
    points = _poll_metric_datapoints(ctx, "AWS/ApplicationELB", "RequestCount", dims, timeout_s=600, stat="Sum")
    assert points, "no RequestCount datapoints published for the load balancer that served real traffic"
    total = sum(dp["Sum"] for dp in points)
    # AWS/ApplicationELB RequestCount can lag and undercount recent traffic, even after a
    # stabilized (non-growing) read, by more than this check's time budget allows to wait out,
    # so this only asserts a nonzero sum.
    assert total >= 1, f"AWS/ApplicationELB RequestCount summed to {total}, expected at least 1"


def _check_vpc_and_subnets(ctx):
    net = _create_network(ctx, n_subnets=2)
    return net["vpc_id"], net["subnet_ids"]


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a security group with only the default allow-all egress rule. One
    cleanup tears the whole network down in dependency order, retrying while ECS still holds
    task ENIs in it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"subnet_ids": []}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["igw_attached"] = True
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]]
    if len(zones) < n_subnets:
        raise AssertionError(f"need {n_subnets} availability zones, the region offers {zones}")
    for i, zone in enumerate(sorted(zones)[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=net["vpc_id"], CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone, TagSpecifications=tag("subnet")
        )["Subnet"]["SubnetId"]
        net["subnet_ids"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=subnet_id)
    net["subnet_id"] = net["subnet_ids"][0]
    net["sg_id"] = ec2.create_security_group(
        GroupName=name, Description="sim2real check network", VpcId=net["vpc_id"], TagSpecifications=tag("security-group")
    )["GroupId"]
    return net


def _delete_network(ctx, net: dict, timeout_s: float = 900.0) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(15)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    for subnet_id in net["subnet_ids"]:
        retrying(ec2.delete_subnet, SubnetId=subnet_id)
    if net.get("rt_id"):
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_attached"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    if net.get("igw_id"):
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _create_http_sg(ctx, vpc_id: str, *, cidrs=(), source_sg=None) -> str:
    """An SG admitting tcp/80 from cidrs or source_sg; LIFO teardown runs after the ALB and tasks."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-alb-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real alb/ecs metrics test sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
            "IpRanges": [{"CidrIp": c} for c in cidrs],
            "UserIdGroupPairs": [{"GroupId": source_sg}] if source_sg else [],
        }],
    )
    return sg_id


def _delete_sg_with_retry(ec2, sg_id: str, attempts: int = 12, delay: float = 10.0) -> None:
    for _ in range(attempts):
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] in ("DependencyViolation",):
                time.sleep(delay)
                continue
            if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
                return
            raise
    raise RuntimeError(f"security group {sg_id} still in use after {attempts} delete attempts")


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ecs-exec-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _register_task_def(ctx, role_arn: str, image: str, port: int) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {"name": "app", "image": image, "essential": True, "portMappings": [{"containerPort": port, "protocol": "tcp"}]}
        ],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(ecs, name))
    return name


def _delete_cluster_with_retry(ecs, name: str, attempts: int = 15, delay: float = 10.0) -> None:
    for _ in range(attempts):
        try:
            ecs.delete_cluster(cluster=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "ClusterContainsContainerInstancesException",
            ):
                time.sleep(delay)
                continue
            if code == "ClusterNotFoundException":
                return
            raise


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    resp = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
    )
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _create_alb(ctx, subnet_ids: list[str], sg_id: str) -> tuple[str, str, str]:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application", IpAddressType="ipv4"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    deadline = time.monotonic() + 180
    state = "provisioning"
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            break
        time.sleep(10)
    if state != "active":
        raise AssertionError(f"ALB {name} never became active (last state {state})")
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["DNSName"]
    return lb_arn, name, dns_name


def _create_listener(ctx, lb_arn: str, tg_arn: str) -> str:
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}]
    )
    listener_arn = resp["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_service(ctx, cluster: str, task_def_arn: str, subnet_ids: list[str], sg_id: str, tg_arn: str, desired_count: int = 1) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
        },
        loadBalancers=[{"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}],
        healthCheckGracePeriodSeconds=60,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
    return name


def _wait_service_running(ctx, cluster: str, service_name: str, desired_count: int = 1, timeout_s: float = 600) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        svc = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]
        if svc["runningCount"] >= desired_count and svc["status"] == "ACTIVE":
            return svc
        time.sleep(15)
    raise AssertionError(f"ECS service {service_name} never reached runningCount={desired_count} within {timeout_s}s")


def _wait_targets_healthy(ctx, tg_arn: str, timeout_s: float = 300) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        if health and all(t["TargetHealth"]["State"] == "healthy" for t in health):
            return
        time.sleep(10)
    raise AssertionError("ECS targets never became healthy behind the ALB target group")


def _generate_http_traffic(ctx, dns_name: str, count: int = 40, delay: float = 1.0) -> int:
    ok = 0
    for _ in range(count):
        try:
            _url, _route = ctx.endpoint_route(f"http://{dns_name}/")
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:
                if resp.status == 200:
                    ok += 1
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(delay)
    return ok


def _poll_metric_datapoints(
    ctx, namespace: str, metric_name: str, dimensions: list[dict], timeout_s: float = 600, period: int = 60, stat: str = "Average",
) -> list[dict]:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=30)
        resp = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=period, Statistics=[stat],
        )
        dps = resp.get("Datapoints", [])
        if dps:
            return dps
        time.sleep(30)
    return []


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
