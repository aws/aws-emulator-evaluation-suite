"""ecs-task-role-assumed-for-container-permissions."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-role-assumed-for-container-permissions"
GROUP = "iam-trust"
SERVICES = ["cloudwatch", "ecr", "ecs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ecs"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A distinct ECS *task* role (not the execution role) is what containers get handed at
    runtime for in-task AWS API calls: `aws sts get-caller-identity` run inside the container
    must report the task role's assumed-role identity, never the execution role's."""
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    _ensure_ecs_service_linked_role(ctx, iam)

    try:
        subnet_id, sg_id = _default_subnet_and_sg(ctx)
    except _NoDefaultVpc as exc:
        raise AssertionError(str(exc)) from exc

    cluster_arn = _create_cluster(ctx, ecs)
    log_group = _create_log_group(ctx)

    exec_role_name = ctx.unique_name("sim2real-ecs-exec-")
    iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc("ecs-tasks.amazonaws.com")),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=_EXEC_POLICY_ARN))
    exec_role_arn = iam.get_role(RoleName=exec_role_name)["Role"]["Arn"]

    task_role_name = ctx.unique_name("sim2real-ecs-taskrole-")
    iam.create_role(
        RoleName=task_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc("ecs-tasks.amazonaws.com")),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=task_role_name))
    task_role_arn = iam.get_role(RoleName=task_role_name)["Role"]["Arn"]

    family = ctx.unique_name("sim2real-ecs-taskrole-td-")
    stream_prefix = "ecs"
    container_name = "app"
    task_def_arn = _register_task_def(
        ctx,
        ecs,
        family=family,
        image="public.ecr.aws/aws-cli/aws-cli:2.36.44",
        command=["sts", "get-caller-identity"],
        execution_role_arn=exec_role_arn,
        task_role_arn=task_role_arn,
        log_group=log_group,
        stream_prefix=stream_prefix,
        container_name=container_name,
    )
    task = _run_task_with_retry(ctx, ecs, cluster_arn, task_def_arn, subnet_id, sg_id)
    task_arn = task["taskArn"]
    final = _wait_task_status(ctx, ecs, cluster_arn, task_arn, {"STOPPED"}, timeout_s=240.0)
    assert final["containers"][0].get("exitCode") == 0, f"aws cli invocation failed: {final['containers'][0]}"

    task_id = task_arn.split("/")[-1]
    stream_name = f"{stream_prefix}/{container_name}/{task_id}"
    text = _wait_log_text(ctx, logs, log_group, stream_name, timeout_s=90.0)

    assert f"assumed-role/{task_role_name}/" in text, f"task role identity not found in output: {text}"
    assert f"assumed-role/{exec_role_name}/" not in text, f"execution role leaked into container identity: {text}"


# ===== helpers =====
class _NoDefaultVpc(Exception):
    pass


def _ensure_ecs_service_linked_role(ctx, iam) -> None:
    """Proactively create (or confirm) AWSServiceRoleForECS so the very first RunTask in
    this account/region doesn't race the lazy service-linked-role creation, which surfaces
    as InvalidParameterException: Unable to assume the service linked role."""
    from botocore.exceptions import ClientError

    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
        return

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForECS")
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            time.sleep(2)
    raise AssertionError("AWSServiceRoleForECS did not become visible within 30s of creation")


def _trust_doc(service_principal: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }


def _default_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise _NoDefaultVpc("no shared network VPC in this account/region to launch a Fargate task into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise _NoDefaultVpc("shared network has no subnets to launch a Fargate task into")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real/ecs/")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _register_task_def(
    ctx,
    ecs,
    family: str,
    image: str,
    command: list[str],
    execution_role_arn: str,
    log_group: str,
    stream_prefix: str,
    container_name: str = "app",
    task_role_arn: str | None = None,
) -> str:
    container: dict[str, Any] = {
        "name": container_name,
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
    kwargs: dict[str, Any] = dict(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[container],
        tags=_ecs_tags_kv(),
    )
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    arn = ecs.register_task_definition(**kwargs)["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_task_with_retry(
    ctx,
    ecs,
    cluster: str,
    task_def_arn: str,
    subnet_id: str,
    sg_id: str,
    retries: int = 15,
    retry_sleep_s: float = 8.0,
) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    last_exc: Exception | None = None
    for _ in range(retries):
        try:
            resp = ecs.run_task(
                cluster=cluster,
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
            if resp.get("failures"):
                raise AssertionError(f"RunTask returned failures: {resp['failures']}")
            return resp["tasks"][0]
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            if code in ("ClientException", "InvalidParameterException") and (
                "assume" in msg or "service linked role" in msg or "service-linked role" in msg
            ):
                time.sleep(retry_sleep_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _wait_task_status(
    ctx, ecs, cluster: str, task_arn: str, target_statuses: set[str], timeout_s: float = 240.0, interval_s: float = 5.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks:
            last = tasks[0]
            if last["lastStatus"] in target_statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"task {task_arn} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _wait_log_text(ctx, logs, log_group: str, stream_name: str, timeout_s: float = 90.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.get_log_events(logGroupName=log_group, logStreamName=stream_name, startFromHead=True)
            events = resp.get("events", [])
            if events:
                return "\n".join(e["message"] for e in events)
        except logs.exceptions.ResourceNotFoundException:
            pass
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
