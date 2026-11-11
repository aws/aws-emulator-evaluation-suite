"""ecs-task-launch-fails-without-ecs-tasks-trust-policy."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-launch-fails-without-ecs-tasks-trust-policy"
GROUP = "iam-trust"
SERVICES = ["cloudwatch", "ecr", "ecs"]

_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask cannot assume an execution role whose trust policy does not include
    ecs-tasks.amazonaws.com as a principal -> ClientException, no task created. The same
    task definition run with a correctly-trusted role (positive control) succeeds."""
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    _ensure_ecs_service_linked_role(ctx, iam)

    try:
        subnet_id, sg_id = _default_subnet_and_sg(ctx)
    except _NoDefaultVpc as exc:
        raise AssertionError(str(exc)) from exc

    cluster_arn = _create_cluster(ctx, ecs)
    log_group = _create_log_group(ctx)

    # Role trusted by the WRONG principal but otherwise fully permissioned -> isolates
    # trust policy as the sole broken factor.
    bad_role_name = ctx.unique_name("sim2real-ecs-badtrust-")
    iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc("states.amazonaws.com")),
        Tags=_iam_tags(),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=bad_role_name, PolicyArn=_EXEC_POLICY_ARN))
    bad_role_arn = iam.get_role(RoleName=bad_role_name)["Role"]["Arn"]

    bad_family = ctx.unique_name("sim2real-ecs-badtrust-td-")
    bad_task_def_arn = _register_task_def(
        ctx,
        ecs,
        family=bad_family,
        image="public.ecr.aws/amazonlinux/amazonlinux:2023",
        command=["/bin/sh", "-c", "exit 0"],
        execution_role_arn=bad_role_arn,
        log_group=log_group,
        stream_prefix="ecs-bad",
    )

    def _attempt() -> None:
        ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=bad_task_def_arn,
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

    got = _error_code_and_message(_attempt)
    want = (
        "ClientException",
        f"ECS was unable to assume the role '{bad_role_arn}' that was provided for this task. Please "
        "verify that the role being passed has the proper trust relationship and permissions and "
        "that your IAM user has permissions to pass this role.",
    )
    assert got == want, f"RunTask with an untrusted execution role raised {got!r}, expected {want!r}"

    # Effect absent: no task was ever created against this cluster for the bad task def.
    listed = ecs.list_tasks(cluster=cluster_arn, family=bad_family)["taskArns"]
    assert listed == [], f"a task was unexpectedly created despite the untrusted role: {listed}"

    # Positive control: same shape, correctly-trusted role -> RunTask succeeds.
    good_role_name = ctx.unique_name("sim2real-ecs-goodtrust-")
    iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc("ecs-tasks.amazonaws.com")),
        Tags=_iam_tags(),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=good_role_name, PolicyArn=_EXEC_POLICY_ARN))
    good_role_arn = iam.get_role(RoleName=good_role_name)["Role"]["Arn"]

    good_family = ctx.unique_name("sim2real-ecs-goodtrust-td-")
    good_task_def_arn = _register_task_def(
        ctx,
        ecs,
        family=good_family,
        image="public.ecr.aws/amazonlinux/amazonlinux:2023",
        command=["/bin/sh", "-c", "exit 0"],
        execution_role_arn=good_role_arn,
        log_group=log_group,
        stream_prefix="ecs-good",
    )
    task = _run_task_with_retry(ctx, ecs, cluster_arn, good_task_def_arn, subnet_id, sg_id)
    final = _wait_task_status(ctx, ecs, cluster_arn, task["taskArn"], {"STOPPED"}, timeout_s=240.0)
    assert final["containers"][0].get("exitCode") == 0, f"positive control failed: {final['containers'][0]}"


# ===== helpers =====
class _NoDefaultVpc(Exception):
    pass


def _ensure_ecs_service_linked_role(ctx, iam) -> None:
    """Proactively create (or confirm) AWSServiceRoleForECS so the very first RunTask in
    this account/region doesn't race the lazy service-linked-role creation, which surfaces
    as InvalidParameterException: Unable to assume the service linked role. Wait for the
    role's own visibility via GetRole (bounded) rather than guessing a propagation delay."""
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForECS")
            return
        except ClientError:
            time.sleep(2.0)
    raise AssertionError("AWSServiceRoleForECS did not become visible via GetRole within 30s")


def _trust_doc(service_principal: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }


def _error_code_and_message(fn) -> tuple[str, str]:
    """(code, message) of a call real AWS refuses. RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused; it succeeded: {result!r}")


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


def _iam_tags() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


def _ecs_tags_kv() -> list[dict[str, str]]:
    """ECS resource tags use lowercase key/value fields, unlike IAM/EC2's Key/Value."""
    return [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}]


def _logs_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:check": CHECK}


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real/ecs/")
    logs.create_log_group(logGroupName=name, tags=_logs_tags())
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
) -> str:
    container = {
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
    arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[container],
        tags=_ecs_tags_kv(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_task_with_retry(
    ctx,
    ecs,
    cluster: str,
    task_def_arn: str,
    subnet_id: str,
    sg_id: str,
    retries: int = 8,
    retry_sleep_s: float = 5.0,
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
            if code == "ClientException" and "assume" in str(exc).lower():
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
