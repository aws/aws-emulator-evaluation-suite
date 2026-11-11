"""ecs-service-cpu-utilization-published-to-cloudwatch."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-cpu-utilization-published-to-cloudwatch"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ecr", "ecs"]

EXEC_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/available-metrics.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A running Fargate service publishes a real (non-zero) CPUUtilization datapoint
    to the AWS/ECS namespace, keyed by ClusterName+ServiceName."""
    subnets, sgs = _default_network(ctx)
    role_arn = _create_execution_role(ctx)
    cluster = _create_cluster(ctx, insights=False)
    task_def_arn, _ = _register_task_def(
        ctx,
        role_arn,
        command=["sh", "-c", "i=0; while true; do i=$((i+1)); done"],
    )
    service = _create_service(ctx, cluster, task_def_arn, subnets, sgs, desired_count=1)
    _wait_for_running_tasks(ctx, cluster, service, 1, timeout_s=300)

    points = _poll_metric_datapoints(
        ctx,
        namespace="AWS/ECS",
        metric_name="CPUUtilization",
        dimensions=[
            {"Name": "ClusterName", "Value": cluster},
            {"Name": "ServiceName", "Value": service},
        ],
        timeout_s=600,
        interval_s=30,
    )
    assert points, (
        "no CPUUtilization datapoints appeared in AWS/ECS for the running service"
    )
    assert any(p["Average"] > 0 for p in points), (
        f"all CPUUtilization datapoints were zero: {points}"
    )


# ===== helpers =====


def _default_network(ctx) -> tuple[list[str], list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError("no shared network VPC available to attach Fargate task ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    if not subnet_ids:
        raise AssertionError("shared network has no subnets available")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    return subnet_ids[:1], [sgs[0]["GroupId"]]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=EXEC_POLICY_ARN)
    )
    return role["Arn"]


def _create_cluster(ctx, insights: bool = False) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(
        clusterName=name,
        settings=[
            {
                "name": "containerInsights",
                "value": "enabled" if insights else "disabled",
            }
        ],
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
    ctx,
    cluster: str,
    task_def_arn: str,
    subnets: list[str],
    sgs: list[str],
    desired_count: int = 1,
) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": sgs,
            "assignPublicIp": "ENABLED",
        }
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
            if e.response["Error"]["Code"] in (
                "InvalidParameterException",
                "ClientException",
            ):
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


def _wait_for_running_tasks(
    ctx, cluster: str, service: str, count: int, timeout_s: float = 300.0
) -> None:
    ecs = ctx.client("ecs")
    running = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][
            0
        ]["runningCount"],
        lambda n: n >= count,
        timeout_s=timeout_s,
        interval_s=10,
    )
    if running < count:
        raise AssertionError(
            f"service never reached {count} running tasks (got {running})"
        )


def _poll_metric_datapoints(
    ctx,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    timeout_s: float = 600.0,
    interval_s: float = 30.0,
) -> list[dict[str, Any]]:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    latest: list[dict[str, Any]] = []
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
            Statistics=["Average"],
        )
        points = resp.get("Datapoints", [])
        if points:
            latest = points
            # The first published datapoint can straddle task startup and read
            # zero even once the busy loop is running; keep polling for a
            # datapoint that actually reflects the load, not merely "some
            # datapoint exists" -- the terminal set must not admit the zero
            # (failure) value while budget remains.
            if any(p["Average"] > 0 for p in points):
                return points
        time.sleep(interval_s)
    return latest


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
