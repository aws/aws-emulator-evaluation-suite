"""ecs-execution-role-trusts-ecs-tasks-service."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-execution-role-trusts-ecs-tasks-service"
GROUP = "iam-trust"
SERVICES = ["cloudwatch", "ecr", "ecs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The ECS execution role's trust policy grants sts:AssumeRole to ecs-tasks.amazonaws.com,
    and the role is actually assumable by ECS to run a real Fargate task (not just correct
    on paper)."""

    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    _ensure_ecs_service_linked_role(ctx, iam)

    role_name = ctx.unique_name("sim2real-ecs-exec-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc("ecs-tasks.amazonaws.com")),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN))
    role = iam.get_role(RoleName=role_name)["Role"]

    doc = role["AssumeRolePolicyDocument"]
    statements = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
    matching = [
        s
        for s in statements
        if s.get("Effect") == "Allow"
        and _action_has(s.get("Action"), "sts:AssumeRole")
        and _principal_has_service(s.get("Principal"), "ecs-tasks.amazonaws.com")
    ]
    assert matching, f"no statement trusts ecs-tasks.amazonaws.com in {doc}"

    # Functional proof: ECS must actually be able to assume this role to run a task.
    try:
        subnet_id, sg_id = _default_subnet_and_sg(ctx)
    except _NoDefaultVpc as exc:
        raise AssertionError(str(exc)) from exc

    cluster_arn = _create_cluster(ctx, ecs)
    log_group = _create_log_group(ctx)
    family = ctx.unique_name("sim2real-ecs-exec-td-")
    task_def_arn = _register_task_def(
        ctx,
        ecs,
        family=family,
        image="public.ecr.aws/amazonlinux/amazonlinux:2023",
        command=["/bin/sh", "-c", "echo trust-ok && exit 0"],
        execution_role_arn=role["Arn"],
        log_group=log_group,
        stream_prefix="ecs",
    )
    task = _run_task_with_retry(ctx, ecs, cluster_arn, task_def_arn, subnet_id, sg_id)
    task_arn = task["taskArn"]
    final = _wait_task_status(ctx, ecs, cluster_arn, task_arn, {"STOPPED"}, timeout_s=240.0)
    containers = final["containers"]
    assert len(containers) == 1, f"expected exactly 1 container in stopped task, got {containers}"
    assert containers[0].get("exitCode") == 0, f"container did not exit cleanly: {containers[0]}"


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
    _wait_for_role_visible(iam, "AWSServiceRoleForECS", timeout_s=60.0)


def _wait_for_role_visible(iam, role_name: str, timeout_s: float, interval_s: float = 3.0) -> None:
    """Bounded poll for IAM's own read-after-create propagation of the service-linked role,
    so RunTask isn't handed a role IAM itself cannot yet see."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"service-linked role {role_name} did not become visible within {timeout_s}s"
    ) from last_exc


def _trust_doc(service_principal: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }


def _action_has(action: Any, wanted: str) -> bool:
    if isinstance(action, str):
        return action == wanted
    if isinstance(action, list):
        return wanted in action
    return False


def _principal_has_service(principal: Any, service: str) -> bool:
    if not isinstance(principal, dict):
        return False
    svc = principal.get("Service")
    if isinstance(svc, str):
        return svc == service
    if isinstance(svc, list):
        return service in svc
    return False


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
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real/ecs/")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
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
    task_role_arn: str | None = None,
) -> str:
    container: dict[str, Any] = {
        "name": "app",
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
    )
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    kwargs["tags"] = [{"key": "sim2real", "value": CHECK}]
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
    assign_public_ip: str = "ENABLED",
    retries: int = 15,
    retry_sleep_s: float = 8.0,
) -> dict[str, Any]:
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
                        "assignPublicIp": assign_public_ip,
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
    assert last_exc is not None, "retry loop exhausted with no recorded exception"
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
