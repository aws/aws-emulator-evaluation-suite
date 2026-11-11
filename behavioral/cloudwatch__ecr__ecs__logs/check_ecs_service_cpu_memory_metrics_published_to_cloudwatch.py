"""ecs-service-cpu-memory-metrics-published-to-cloudwatch."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-service-cpu-memory-metrics-published-to-cloudwatch"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


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
    """A running Fargate ECS service publishes CPUUtilization/MemoryUtilization to AWS/ECS."""
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")

    subnet_id, sg_id = _default_network(ctx)
    exec_role_arn = _create_ecs_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(ecs, cluster_name))

    log_group = ctx.unique_name("/sim2real/behav-ecs-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    family = ctx.unique_name("sim2real-behav-td-")
    reg = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sh", "-c", "while true; do echo alive; sleep 5; done"],
                "essential": True,
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    _create_service_retrying_role_propagation(
        ecs, cluster_name, service_name, task_def_arn, subnet_id, sg_id
    )

    def _stop_service() -> None:
        ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=0)
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)

    ctx.on_cleanup(_stop_service)

    waiter = ecs.get_waiter("services_stable")
    waiter.wait(
        cluster=cluster_name,
        services=[service_name],
        WaiterConfig={"Delay": 2, "MaxAttempts": 300},
    )

    dimensions = [
        {"Name": "ClusterName", "Value": cluster_name},
        {"Name": "ServiceName", "Value": service_name},
    ]
    cpu_points = _wait_metric_datapoints(
        ctx, "AWS/ECS", "CPUUtilization", dimensions, timeout_s=480
    )
    assert cpu_points, (
        "no CPUUtilization datapoints published for the running ECS service"
    )
    mem_points = _wait_metric_datapoints(
        ctx, "AWS/ECS", "MemoryUtilization", dimensions, timeout_s=180
    )
    assert mem_points, (
        "no MemoryUtilization datapoints published for the running ECS service"
    )


# ===== helpers =====
def _default_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to launch the ECS task into"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-ecsexec-")
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
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_service_retrying_role_propagation(
    ecs,
    cluster_name: str,
    service_name: str,
    task_def_arn: str,
    subnet_id: str,
    sg_id: str,
) -> None:
    """CreateService, retrying while the just-created execution role is still propagating.

    IAM role/policy attachment is eventually consistent, so ECS answers with a transient
    ClientException/InvalidParameterException naming the role until it can assume it. That is
    real evidence to retry on, unlike a fixed pre-emptive sleep with no way to know it waited
    long enough.
    """
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition=task_def_arn,
                desiredCount=1,
                launchType="FARGATE",
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
                tags=[{"key": "sim2real", "value": "true"}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if (
                code in ("ClientException", "InvalidParameterException")
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _delete_cluster_with_retry(
    ecs, cluster_name: str, timeout_s: float = 40.0, interval_s: float = 5.0
) -> None:
    """DeleteCluster, retrying while the just force-deleted service's tasks are still draining.

    ECS refuses to delete a cluster that still has tasks or services attached, and a Fargate
    service's ENIs/tasks do not vanish the instant DeleteService(force=True) returns -- so this
    retries on the specific "still attached" errors instead of assuming force-delete was instant.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if (
                code
                in (
                    "ClusterContainsTasksException",
                    "ClusterContainsServicesException",
                    "ClusterContainsContainerInstancesException",
                )
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _wait_metric_datapoints(
    ctx,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    timeout_s: float,
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
            Statistics=["Average"],
        )
        points = resp.get("Datapoints", [])
        if points:
            return points
        time.sleep(20)
    return []



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
