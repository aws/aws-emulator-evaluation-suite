"""ecs-log-retention-policy-applied-to-loggroup."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-log-retention-policy-applied-to-loggroup"
GROUP = "log-delivery"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pre-created log group with an explicit retention setting keeps that retention after an
    ECS task delivers logs into it: ECS does not reset retention on an existing group."""
    net = _get_network_config(ctx)
    role = _create_execution_role(ctx, "retention")
    cluster = _create_cluster(ctx)
    log_group = _create_log_group(ctx, "retention", retention_days=1)

    task_def_arn = _register_task_def(
        ctx,
        "retention",
        containers=[
            _container_def(ctx, "app", _IMAGE, ["sh", "-c", "echo hello-retention-check; sleep 2"], log_group, "ecs")
        ],
        execution_role_arn=role["arn"],
    )
    task_arn = _run_task(ctx, cluster, task_def_arn, net)
    task = _wait_for_task_stopped(ctx, cluster, task_arn, timeout_s=300)
    assert task["lastStatus"] == "STOPPED"
    assert task["containers"][0]["exitCode"] == 0

    logs = ctx.client("logs")
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    matching = [g for g in groups if g["logGroupName"] == log_group]
    assert len(matching) == 1
    assert matching[0]["retentionInDays"] == 1

    task_id = task_arn.rsplit("/", 1)[-1]
    stream_name = f"ecs/app/{task_id}"
    messages = _get_log_messages(ctx, log_group, stream_name, timeout_s=60)
    assert any("hello-retention-check" in m for m in messages)


# ===== helpers =====

def _get_network_config(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to launch ECS Fargate tasks into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch ECS Fargate tasks into")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}, {"Name": "vpc-id", "Values": [vpc_id]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return {"subnets": [subnet_id], "security_groups": [sgs[0]["GroupId"]]}


def _create_execution_role(ctx, suffix: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-ecsexec-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
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


def _create_log_group(ctx, suffix: str, retention_days: int | None = None) -> str:
    logs = ctx.client("logs")
    name = f"/ecs/{ctx.unique_name(f'sim2real-lg-{suffix}-')}"
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    if retention_days is not None:
        logs.put_retention_policy(logGroupName=name, retentionInDays=retention_days)
    return name


def _container_def(ctx, name: str, image: str, command: list, log_group: str, stream_prefix: str) -> dict:
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


def _register_task_def(ctx, family_suffix: str, containers: list, execution_role_arn: str) -> str:
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


def _run_task(ctx, cluster: str, task_def_arn: str, net: dict, timeout_s: float = 90.0) -> str:
    """Bounded-retries RunTask past IAM's eventual-consistency window for the execution
    role's just-attached policy: ECS synchronously rejects RunTask with a ClientException
    ("unable to assume the role") until the attachment is visible to it."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last_failures = None
    last_error = None
    while time.monotonic() < deadline:
        try:
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
        except ClientError as exc:
            last_error = exc
            time.sleep(5)
            continue
        if resp.get("tasks"):
            return resp["tasks"][0]["taskArn"]
        last_failures = resp.get("failures")
        time.sleep(5)
    raise AssertionError(
        f"run_task never scheduled a task within {timeout_s}s; failures={last_failures}; last_error={last_error}"
    )


def _wait_for_task_stopped(ctx, cluster: str, task_arn: str, timeout_s: float = 300.0, interval_s: float = 6.0) -> dict:
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


def _get_log_messages(ctx, log_group: str, stream_name: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> list:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.get_log_events(logGroupName=log_group, logStreamName=stream_name, startFromHead=True)
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(interval_s)
            continue
        events = resp.get("events", [])
        if events:
            return [e["message"] for e in events]
        time.sleep(interval_s)
    raise AssertionError(f"no log events appeared in {log_group}/{stream_name} within {timeout_s}s")



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
