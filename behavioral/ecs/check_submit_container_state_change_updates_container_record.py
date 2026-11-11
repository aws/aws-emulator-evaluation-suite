"""submit-container-state-change-updates-container-record."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-container-state-change-updates-container-record"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SubmitContainerStateChange (the API the ECS agent uses to report a
    container's status) updates the container-level lastStatus/exitCode/reason
    inside the task record returned by DescribeTasks."""
    ecs = ctx.client("ecs")
    setup = _fargate_task_setup(ctx)
    cluster, task_arn, container_name = setup["cluster"], setup["task_arn"], setup["container_name"]

    before = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
    before_container = next(c for c in before["containers"] if c["name"] == container_name)
    assert before_container["lastStatus"] != "STOPPED", before_container["lastStatus"]

    ecs.submit_container_state_change(
        cluster=cluster,
        task=task_arn,
        containerName=container_name,
        status="STOPPED",
        exitCode=42,
        reason="sim2real-manual-container-exit",
    )

    after = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
    after_container = next(c for c in after["containers"] if c["name"] == container_name)
    assert after_container["lastStatus"] == "STOPPED", after_container["lastStatus"]
    assert after_container.get("exitCode") == 42, after_container.get("exitCode")
    assert after_container.get("reason") == "sim2real-manual-container-exit", after_container.get("reason")


# ===== helpers =====

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecsx"},
]
_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


def _fargate_network(ctx):
    """(subnet, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return net.subnet_ids[0], net.security_group_id


def _create_task_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsx-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_NET_TAGS
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _fargate_task_setup(ctx):
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _fargate_network(ctx)
    exec_role_arn = _create_task_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-ecsx-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecsx-taskdef-")
    container_name = "app"
    reg = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        tags=_ECS_TAGS,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    tasks = []
    last_failures = None
    last_error = None
    deadline = time.monotonic() + 180.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
            )
        except ClientError as exc:
            # Freshly-created IAM roles are eventually consistent -- ECS can
            # transiently fail to assume the just-created execution role for
            # a short window after CreateRole/AttachRolePolicy. Retry rather
            # than treat this as a real rejection.
            last_error = exc
            if exc.response["Error"]["Code"] == "ClientException" and "unable to assume the role" in str(exc):
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
                continue
            raise
        tasks = resp.get("tasks", [])
        if tasks:
            break
        last_failures = resp.get("failures")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not tasks:
        raise AssertionError(f"RunTask never placed a task: failures={last_failures} last_error={last_error}")
    task = tasks[0]
    task_arn = task["taskArn"]

    def _stop_and_wait():
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
            if not d or d[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_stop_and_wait)

    return {
        "cluster": cluster_name,
        "task_arn": task_arn,
        "task": task,
        "container_name": container_name,
    }



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
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
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
