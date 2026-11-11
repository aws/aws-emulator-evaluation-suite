"""ecs-service-cpu-memory-metrics-in-cloudwatch."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-cpu-memory-metrics-in-cloudwatch"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-metrics.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A running Fargate ECS service publishes CPUUtilization/MemoryUtilization under AWS/ECS."""
    vpc_id, subnet_id = _get_default_vpc_and_subnet(ctx)
    sg_id = _create_http_sg(ctx, vpc_id)
    role_arn = _create_execution_role(ctx)
    command = ["sh", "-c", "dd if=/dev/zero of=/tmp/fill bs=1M count=64 & i=0; while true; do i=$((i+1)); done"]
    task_def_arn = _register_task_def(ctx, role_arn, "public.ecr.aws/docker/library/busybox:latest", command)
    cluster = _create_cluster(ctx, container_insights=False)
    service = _create_service(ctx, cluster, task_def_arn, [subnet_id], sg_id)
    _wait_service_running(ctx, cluster, service, desired_count=1, timeout_s=600)

    dims = [{"Name": "ClusterName", "Value": cluster}, {"Name": "ServiceName", "Value": service}]
    cpu_points = _poll_metric_datapoints(ctx, "AWS/ECS", "CPUUtilization", dims, timeout_s=600)
    mem_points = _poll_metric_datapoints(ctx, "AWS/ECS", "MemoryUtilization", dims, timeout_s=600)

    assert cpu_points, "no CPUUtilization datapoints published under AWS/ECS for the running service"
    assert mem_points, "no MemoryUtilization datapoints published under AWS/ECS for the running service"
    assert any(dp["Average"] > 0 for dp in cpu_points), f"all CPUUtilization datapoints were zero: {cpu_points}"
    assert any(dp["Average"] > 0 for dp in mem_points), f"all MemoryUtilization datapoints were zero: {mem_points}"


# ===== helpers =====

def _get_default_vpc_and_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place the ECS Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    chosen = public or [s["SubnetId"] for s in subnets]
    if not chosen:
        raise AssertionError("shared network has no subnets available")
    return vpc_id, chosen[0]


def _create_http_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ecs-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real ecs metrics test sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, sg_id))
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
    # Cleanups run last-in first-out: the policy is detached before the role is deleted.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _register_task_def(ctx, role_arn: str, image: str, command: list[str]) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[{"name": "app", "image": image, "command": command, "essential": True}],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _create_cluster(ctx, container_insights: bool) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "enabled" if container_insights else "disabled"}],
    )
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    return name


def _create_service(ctx, cluster: str, task_def_arn: str, subnet_ids: list[str], sg_id: str, desired_count: int = 1) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-svc-")
    net_cfg = {"awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}
    deadline = time.monotonic() + 60
    while True:
        try:
            ecs.create_service(
                cluster=cluster,
                serviceName=name,
                taskDefinition=task_def_arn,
                desiredCount=desired_count,
                launchType="FARGATE",
                networkConfiguration=net_cfg,
            )
            break
        except ClientError as e:
            # IAM role/policy attachment propagation is eventually consistent: ECS may
            # reject the service create until the execution role becomes assumable.
            if e.response["Error"]["Code"] in ("InvalidParameterException", "ClientException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
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


def _poll_metric_datapoints(
    ctx, namespace: str, metric_name: str, dimensions: list[dict], timeout_s: float = 600, period: int = 60,
) -> list[dict]:
    # The task's very first CPU/memory sample can legitimately read 0 (no prior cpuacct
    # delta to compute a rate from), so keep accumulating datapoints across polls until a
    # non-zero one shows up or the budget runs out, rather than returning on the first
    # non-empty response.
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    by_timestamp: dict = {}
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=30)
        resp = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=period, Statistics=["Average"],
        )
        for dp in resp.get("Datapoints", []):
            by_timestamp[dp["Timestamp"]] = dp
        if any(dp["Average"] > 0 for dp in by_timestamp.values()):
            return list(by_timestamp.values())
        time.sleep(30)
    return list(by_timestamp.values())


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
