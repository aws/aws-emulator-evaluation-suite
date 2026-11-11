"""alb-target-response-time-metric-in-cloudwatch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alb-target-response-time-metric-in-cloudwatch"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """TargetResponseTime reflects real measured latency from the ECS backend, not a stub constant."""
    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:3]
    alb_sg = _create_http_sg(ctx, vpc_id, cidrs=ctx.ingress_cidrs())
    task_sg = _create_http_sg(ctx, vpc_id, source_sg=alb_sg)
    role_arn = _create_execution_role(ctx)
    task_def_arn = _register_task_def(ctx, role_arn, "public.ecr.aws/docker/library/httpd:latest", port=80)
    cluster = _create_cluster(ctx)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn, dns_name = _create_alb(ctx, subnet_ids, alb_sg)
    _create_listener(ctx, lb_arn, tg_arn)
    service = _create_service(ctx, cluster, task_def_arn, subnet_ids, task_sg, tg_arn)
    _wait_service_running(ctx, cluster, service, timeout_s=600)
    _wait_targets_healthy(ctx, tg_arn, timeout_s=300)

    latencies = _generate_http_traffic_with_latency(ctx, dns_name, count=30, delay=1.0)
    assert len(latencies) >= 10, f"too few successful requests against the ALB to measure latency: {latencies}"

    lb_dim_value = "/".join(lb_arn.split("/")[-3:])
    dims = [{"Name": "LoadBalancer", "Value": lb_dim_value}]
    points = _poll_metric_datapoints(ctx, "AWS/ApplicationELB", "TargetResponseTime", dims, timeout_s=600, stat="Average")
    assert points, "no TargetResponseTime datapoints published despite real traffic served by ECS targets"
    avg = sum(dp["Average"] for dp in points) / len(points)
    # A genuine measurement of a fast in-region HTTP response: strictly positive (never a hardcoded
    # 0.0) and well under a second for a trivial static page served by Apache on Fargate.
    assert avg > 0.0, f"TargetResponseTime average was {avg}, expected a strictly positive real latency"
    assert avg < 5.0, f"TargetResponseTime average {avg}s implausibly high for a local static page"


def _create_http_sg(ctx, vpc_id: str, *, cidrs=(), source_sg=None) -> str:
    """An SG admitting tcp/80 from cidrs or source_sg; LIFO teardown runs after the ALB and tasks."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-alb-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real alb/ecs latency test sg",
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
            if e.response["Error"]["Code"] == "DependencyViolation":
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
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
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


def _create_alb(ctx, subnet_ids: list[str], sg_id: str) -> tuple[str, str]:
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
    return lb_arn, dns_name


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


def _generate_http_traffic_with_latency(ctx, dns_name: str, count: int = 30, delay: float = 1.0) -> list[float]:
    target, route = ctx.endpoint_route(f"http://{dns_name}/")
    latencies = []
    for _ in range(count):
        start = time.monotonic()
        try:
            with urllib.request.urlopen(urllib.request.Request(target, headers=route), timeout=5) as resp:
                if resp.status == 200:
                    latencies.append(time.monotonic() - start)
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(delay)
    return latencies


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
