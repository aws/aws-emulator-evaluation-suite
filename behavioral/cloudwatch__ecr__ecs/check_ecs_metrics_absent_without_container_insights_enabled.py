"""ecs-metrics-absent-without-container-insights-enabled."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-metrics-absent-without-container-insights-enabled"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ecr", "ecs"]

EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A cluster with Container Insights disabled publishes no ECS/ContainerInsights datapoints for
    its running service over the same window in which an otherwise identical cluster with
    Container Insights enabled does."""
    window_start = datetime.now(timezone.utc)
    subnets, sgs = _default_network(ctx)
    role_arn = _create_execution_role(ctx)

    cluster_disabled = _create_cluster(ctx, insights=False)
    task_def_disabled, _ = _register_task_def(
        ctx, role_arn, command=["sh", "-c", "i=0; while true; do i=$((i+1)); done"]
    )
    service_disabled = _create_service(ctx, cluster_disabled, task_def_disabled, subnets, sgs, desired_count=1)

    cluster_enabled = _create_cluster(ctx, insights=True)
    task_def_enabled, _ = _register_task_def(
        ctx, role_arn, command=["sh", "-c", "i=0; while true; do i=$((i+1)); done"]
    )
    service_enabled = _create_service(ctx, cluster_enabled, task_def_enabled, subnets, sgs, desired_count=1)

    _wait_for_running_tasks(ctx, cluster_disabled, service_disabled, 1, timeout_s=300)
    _wait_for_running_tasks(ctx, cluster_enabled, service_enabled, 1, timeout_s=300)

    # Positive control: the only difference is the containerInsights cluster
    # setting, and this cluster's running service DOES produce Container
    # Insights datapoints.
    enabled_points = _poll_metric_datapoints(
        ctx,
        "ECS/ContainerInsights",
        "CpuUtilized",
        [
            {"Name": "ServiceName", "Value": service_enabled},
            {"Name": "ClusterName", "Value": cluster_enabled},
        ],
        timeout_s=600,
        interval_s=30,
    )
    assert enabled_points, "positive control failed: CI-enabled cluster produced no ECS/ContainerInsights data"

    # Effect-absent: over the identical wall-clock window, the CI-disabled
    # cluster's service never appears in ECS/ContainerInsights, even though
    # its task is demonstrably running real work (classic AWS/ECS metric
    # confirms the service is alive and busy).
    classic_points = _poll_metric_datapoints(
        ctx,
        "AWS/ECS",
        "CPUUtilization",
        [
            {"Name": "ClusterName", "Value": cluster_disabled},
            {"Name": "ServiceName", "Value": service_disabled},
        ],
        timeout_s=180,
        interval_s=20,
    )
    assert classic_points, "CI-disabled service never showed up in classic AWS/ECS metrics either"

    cw = ctx.client("cloudwatch")
    window_end = datetime.now(timezone.utc)
    ci_resp = cw.get_metric_statistics(
        Namespace="ECS/ContainerInsights",
        MetricName="CpuUtilized",
        Dimensions=[
            {"Name": "ServiceName", "Value": service_disabled},
            {"Name": "ClusterName", "Value": cluster_disabled},
        ],
        StartTime=window_start,
        EndTime=window_end,
        Period=60,
        Statistics=["Average"],
    )
    assert ci_resp.get("Datapoints", []) == [], (
        f"CI-disabled cluster unexpectedly has ECS/ContainerInsights datapoints: {ci_resp['Datapoints']}"
    )


# ===== helpers =====

def _default_network(ctx) -> tuple[list[str], list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to attach Fargate task ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    if not subnet_ids:
        raise AssertionError("shared network has no subnets available")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return subnet_ids[:1], [sgs[0]["GroupId"]]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN))
    return role["Arn"]


def _create_cluster(ctx, insights: bool = False) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "enabled" if insights else "disabled"}],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_task_def(
    ctx,
    execution_role_arn: str,
    command: list[str],
    cpu: str = "256",
    memory: str = "512",
    log_group: str | None = None,
) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-taskdef-")
    container: dict[str, Any] = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": command,
    }
    if log_group:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "sim2real",
            },
        }
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu=cpu,
        memory=memory,
        executionRoleArn=execution_role_arn,
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn, family


def _create_service(
    ctx, cluster: str, task_def_arn: str, subnets: list[str], sgs: list[str], desired_count: int = 1
) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets, "securityGroups": sgs, "assignPublicIp": "ENABLED"}
    }
    last_err = None
    for _ in range(10):
        try:
            ecs.create_service(
                cluster=cluster,
                serviceName=name,
                taskDefinition=task_def_arn,
                desiredCount=desired_count,
                launchType="FARGATE",
                networkConfiguration=net_cfg,
                tags=[{"key": "sim2real", "value": "true"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidParameterException", "ClientException"):
                time.sleep(5)
                continue
            raise
    else:
        raise last_err

    def _cleanup() -> None:
        ecs.update_service(cluster=cluster, service=name, desiredCount=0)
        _poll_until(
            lambda: len(ecs.list_tasks(cluster=cluster, serviceName=name)["taskArns"]),
            lambda n: n == 0,
            timeout_s=180,
            interval_s=5,
        )
        ecs.delete_service(cluster=cluster, service=name, force=True)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_running_tasks(ctx, cluster: str, service: str, count: int, timeout_s: float = 300.0) -> None:
    ecs = ctx.client("ecs")
    running = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][0]["runningCount"],
        lambda n: n >= count,
        timeout_s=timeout_s,
        interval_s=10,
    )
    if running < count:
        raise AssertionError(f"service never reached {count} running tasks (got {running})")


def _poll_metric_datapoints(
    ctx,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    timeout_s: float = 600.0,
    interval_s: float = 30.0,
    stat: str = "Average",
) -> list[dict[str, Any]]:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=20)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=[stat],
        )
        points = resp.get("Datapoints", [])
        if points:
            return points
        time.sleep(interval_s)
    return []


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


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
