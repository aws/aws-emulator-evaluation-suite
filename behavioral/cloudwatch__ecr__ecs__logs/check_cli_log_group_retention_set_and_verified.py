"""cli-log-group-retention-set-and-verified."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-log-group-retention-set-and-verified"
GROUP = "cli-roundtrip"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI-created log group's retention policy is honored (survives ingestion), and an ECS
    Fargate task's container logs actually land in that retention-configured log group."""
    require_tools("aws")

    logs = ctx.client("logs")
    ecs = ctx.client("ecs")

    marker = ctx.unique_name("sim2real-retention-marker-")
    log_group = "/sim2real/" + ctx.unique_name("retention-")
    cluster_name = ctx.unique_name("sim2real-cluster-")
    role_name = ctx.unique_name("sim2real-exec-role-")
    family = ctx.unique_name("sim2real-taskdef-")
    container_name = "app"
    # No ECR dependency here: reference the public ECR Public gallery image directly, which
    # requires no registry auth and needs no push of our own — this check's SERVICES are only
    # logs + ecs.
    public_image = "public.ecr.aws/docker/library/busybox:1.36"

    _run_aws(ctx, "logs", "create-log-group", "--log-group-name", log_group, "--tags", "sim2real=true")
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    _run_aws(ctx, "logs", "put-retention-policy", "--log-group-name", log_group, "--retention-in-days", "1")

    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert len(described) == 1, f"expected exactly one log group named {log_group!r}, got: {described}"
    assert described[0]["retentionInDays"] == 1, f"retention not honored: {described[0]}"

    role_arn = _create_execution_role(ctx, role_name)
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))
    subnet_id, sg_id = _default_subnet_and_sg(ctx)

    register_resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": public_image,
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; sleep 3"],
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
    task_def_arn = register_resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    task_arn = _run_task_with_role_retry(ctx, ecs, cluster_name, task_def_arn, subnet_id, sg_id, timeout_s=90.0)

    _poll_until(
        lambda: (ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"] or [None])[0],
        lambda t: t is not None and t.get("lastStatus") == "STOPPED",
        timeout_s=300.0,
        interval_s=10.0,
    )

    matches = _poll_until(
        lambda: logs.filter_log_events(logGroupName=log_group)["events"],
        lambda evs: any(marker in e["message"] for e in evs),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert any(marker in e["message"] for e in matches), (
        f"marker {marker!r} not found in log group events: {[e['message'] for e in matches]}"
    )

    # retention must still be in effect after ingestion (not reset by log delivery / stream creation)
    described_after = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]
    assert described_after["retentionInDays"] == 1, f"retention changed after ingestion: {described_after}"


# ===== helpers =====

def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last}")


def _create_execution_role(ctx, role_name: str) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        )
    )
    _poll_until(
        lambda: iam.get_role(RoleName=role_name),
        lambda resp: resp["Role"]["Arn"] == role_arn,
        timeout_s=20.0,
        interval_s=2.0,
    )
    return role_arn


def _default_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available to launch a Fargate task")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _run_task_with_role_retry(ctx, ecs, cluster_name, task_def_arn, subnet_id, sg_id, timeout_s: float) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
                count=1,
            )
            failures = resp.get("failures", [])
            if failures:
                last_error = failures
                time.sleep(5.0)
                continue
            return resp["tasks"][0]["taskArn"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("InvalidParameterException", "ClientException") and "assume" in message.lower():
                last_error = message
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"run_task never succeeded within {timeout_s}s; last error: {last_error}")



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
