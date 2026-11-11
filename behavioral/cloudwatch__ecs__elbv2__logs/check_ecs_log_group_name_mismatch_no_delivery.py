"""ecs-log-group-name-mismatch-no-delivery."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-log-group-name-mismatch-no-delivery"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Negative: a task whose awslogs group was never created (no awslogs-create-group) stops
    without creating the group or delivering events, while an identical task pointed at an
    existing group delivers logs with the same execution role."""
    net = _get_network_config(ctx)
    cluster = _create_cluster(ctx)
    role = _create_execution_role(ctx, "mismatch")

    # --- negative: log group referenced by the task definition was never created ---
    logs = ctx.client("logs")
    missing_log_group = f"/ecs/{ctx.unique_name('sim2real-lg-missing-')}"
    task_def_neg = _register_task_def(
        ctx,
        "mismatch-neg",
        containers=[
            _container_def(
                ctx,
                "app",
                _IMAGE,
                ["sh", "-c", "echo should-never-be-delivered; sleep 2"],
                missing_log_group,
                "ecs",
            )
        ],
        execution_role_arn=role["arn"],
    )
    task_neg = _run_task_tolerating_role_propagation(ctx, cluster, task_def_neg, net)

    assert task_neg["lastStatus"] == "STOPPED"
    reason = task_neg.get("stoppedReason") or ""
    assert reason.startswith("ResourceInitializationError")

    groups = logs.describe_log_groups(logGroupNamePrefix=missing_log_group)["logGroups"]
    assert (
        groups == []
    )  # the mismatched log group was never created -> no delivery happened

    # --- positive control: identical setup, log group pre-created and correctly named ---
    existing_log_group = _create_log_group(ctx, "mismatch-pos")
    task_def_pos = _register_task_def(
        ctx,
        "mismatch-pos",
        containers=[
            _container_def(
                ctx,
                "app",
                _IMAGE,
                ["sh", "-c", "echo delivered-with-matching-group; sleep 2"],
                existing_log_group,
                "ecs",
            )
        ],
        execution_role_arn=role["arn"],
    )
    task_pos = _run_task_tolerating_role_propagation(ctx, cluster, task_def_pos, net)
    task_arn_pos = task_pos["taskArn"]

    assert task_pos["lastStatus"] == "STOPPED"
    assert task_pos.get("stoppedReason") == "Essential container in task exited"
    assert task_pos["containers"][0]["exitCode"] == 0

    task_id_pos = task_arn_pos.rsplit("/", 1)[-1]
    stream_name_pos = f"ecs/app/{task_id_pos}"
    messages = _get_log_messages(ctx, existing_log_group, stream_name_pos, timeout_s=60)
    assert any("delivered-with-matching-group" in m for m in messages)


# ===== helpers =====


def _get_network_config(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to launch ECS Fargate tasks into"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "shared network VPC has no subnets to launch ECS Fargate tasks into"
        )
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": ["default"]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return {"subnets": [subnet_id], "security_groups": [sgs[0]["GroupId"]]}


def _create_execution_role(ctx, suffix: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-ecsexec-{suffix}-")
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
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    return {"name": role_name, "arn": role_arn}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecscluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    return name


def _create_log_group(ctx, suffix: str) -> str:
    logs = ctx.client("logs")
    name = f"/ecs/{ctx.unique_name(f'sim2real-lg-{suffix}-')}"
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _container_def(
    ctx, name: str, image: str, command: list, log_group: str, stream_prefix: str
) -> dict:
    return {
        "name": name,
        "image": image,
        "essential": True,
        "command": command,
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": stream_prefix,
            },
        },
    }


def _register_task_def(
    ctx, family_suffix: str, containers: list, execution_role_arn: str
) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name(f"sim2real-taskdef-{family_suffix}-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=containers,
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _run_task(ctx, cluster: str, task_def_arn: str, net: dict) -> str:
    ecs = ctx.client("ecs")
    last_failures = None
    for _ in range(6):
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=task_def_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["security_groups"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
        if resp.get("tasks"):
            return resp["tasks"][0]["taskArn"]
        last_failures = resp.get("failures")
        time.sleep(5)
    raise AssertionError(f"run_task never scheduled a task; failures={last_failures}")


def _run_task_tolerating_role_propagation(
    ctx, cluster: str, task_def_arn: str, net: dict, timeout_s: float = 90.0
) -> dict:
    """A freshly created execution role can take a few seconds to propagate to
    ECS: confirmed on real AWS, RunTask itself raises ClientException with a
    message naming role assumption ("ECS was unable to assume the role ...")
    rather than scheduling the task at all. Retry only on that specific signal,
    bounded by timeout_s, so a genuine ResourceInitializationError from a
    missing log group or missing logs permission is never retried away."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            task_arn = _run_task(ctx, cluster, task_def_arn, net)
        except ClientError as err:
            message = err.response.get("Error", {}).get("Message", "")
            if "unable to assume the role" in message and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
        task = _wait_for_task_stopped(ctx, cluster, task_arn, timeout_s=300)
        reason = (task.get("stoppedReason") or "").lower()
        if "unable to assume role" not in reason or time.monotonic() >= deadline:
            return task
        time.sleep(5)


def _wait_for_task_stopped(
    ctx, cluster: str, task_arn: str, timeout_s: float = 300.0, interval_s: float = 6.0
) -> dict:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks:
            last = tasks[0]
            if last["lastStatus"] == "STOPPED":
                return last
        time.sleep(interval_s)
    raise AssertionError(f"task did not reach STOPPED within {timeout_s}s; last={last}")


def _get_log_messages(
    ctx,
    log_group: str,
    stream_name: str,
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> list:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream_name, startFromHead=True
            )
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(interval_s)
            continue
        events = resp.get("events", [])
        if events:
            return [e["message"] for e in events]
        time.sleep(interval_s)
    raise AssertionError(
        f"no log events appeared in {log_group}/{stream_name} within {timeout_s}s"
    )



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
