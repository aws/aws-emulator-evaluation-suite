"""ecs-task-fails-log-delivery-without-logs-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-fails-log-delivery-without-logs-permission"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Negative: an execution role without logs:CreateLogStream/PutLogEvents leaves an existing log
    group with no stream or events, while the same task definition with
    AmazonECSTaskExecutionRolePolicy attached delivers logs."""
    net = _get_network_config(ctx)
    cluster = _create_cluster(ctx)

    # --- negative: execution role with zero attached policies (no logs perms) ---
    role_neg = _create_execution_role(ctx, "neg", attach_execution_policy=False)
    log_group_neg = _create_log_group(ctx, "neg")
    task_def_neg = _register_task_def(
        ctx,
        "neg",
        containers=[
            _container_def(ctx, "app", _IMAGE, ["sh", "-c", "echo should-never-be-delivered; sleep 2"], log_group_neg, "ecs")
        ],
        execution_role_arn=role_neg["arn"],
    )
    task_arn_neg = _run_task(ctx, cluster, task_def_neg, net)
    task_neg = _wait_for_task_stopped(ctx, cluster, task_arn_neg, timeout_s=300)

    assert task_neg["lastStatus"] == "STOPPED", (
        f"task with a no-permission execution role did not stop; lastStatus={task_neg['lastStatus']!r}"
    )
    reason = task_neg.get("stoppedReason") or ""
    assert reason.startswith("ResourceInitializationError"), (
        f"expected a ResourceInitializationError from the awslogs driver init, got: {reason!r}"
    )

    logs = ctx.client("logs")
    neg_streams = logs.describe_log_streams(logGroupName=log_group_neg)["logStreams"]
    assert neg_streams == [], f"no log stream should exist for the denied task, found {neg_streams!r}"

    # --- positive control: same shape, role has the standard execution policy ---
    role_pos = _create_execution_role(ctx, "pos", attach_execution_policy=True)
    log_group_pos = _create_log_group(ctx, "pos")
    task_def_pos = _register_task_def(
        ctx,
        "pos",
        containers=[
            _container_def(ctx, "app", _IMAGE, ["sh", "-c", "echo delivered-with-permission; sleep 2"], log_group_pos, "ecs")
        ],
        execution_role_arn=role_pos["arn"],
    )
    task_arn_pos = _run_task(ctx, cluster, task_def_pos, net)
    task_pos = _wait_for_task_stopped(ctx, cluster, task_arn_pos, timeout_s=300)

    assert task_pos["lastStatus"] == "STOPPED", (
        f"control task with a permissioned execution role did not stop; lastStatus={task_pos['lastStatus']!r}"
    )
    assert task_pos.get("stoppedReason") == "Essential container in task exited", (
        f"control task stopped for an unexpected reason: {task_pos.get('stoppedReason')!r}"
    )
    assert task_pos["containers"][0]["exitCode"] == 0, (
        f"control container exited non-zero: {task_pos['containers'][0].get('exitCode')!r}"
    )

    task_id_pos = task_arn_pos.rsplit("/", 1)[-1]
    stream_name_pos = f"ecs/app/{task_id_pos}"
    messages = _get_log_messages(ctx, log_group_pos, stream_name_pos, timeout_s=60)
    assert any("delivered-with-permission" in m for m in messages), (
        f"expected marker 'delivered-with-permission' in delivered log events, got: {messages!r}"
    )


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


def _create_execution_role(ctx, suffix: str, attach_execution_policy: bool) -> dict:
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if attach_execution_policy:
        policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _wait_for_policy_attached(ctx, role_name, policy_arn)
    else:
        _wait_for_role_readable(ctx, role_name)
    return {"name": role_name, "arn": role_arn}


def _wait_for_role_readable(ctx, role_name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """Bounded wait for IAM read-after-write consistency on a just-created role."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except iam.exceptions.NoSuchEntityException:
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became readable via get_role within {timeout_s}s")


def _wait_for_policy_attached(ctx, role_name: str, policy_arn: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """Bounded wait for IAM read-after-write consistency on a just-attached managed policy."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        if any(p["PolicyArn"] == policy_arn for p in attached):
            return
        time.sleep(interval_s)
    raise AssertionError(f"policy {policy_arn} never appeared attached to {role_name} within {timeout_s}s")


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
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real:managed", "value": "true"}])

    def _drop() -> None:
        # A just-stopped task can still count against the cluster for a few seconds, so
        # DeleteCluster is retried on exactly those refusals; a missing cluster is already gone.
        deadline = time.monotonic() + 25.0
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException",
                ) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_drop)
    return name


def _create_log_group(ctx, suffix: str) -> str:
    logs = ctx.client("logs")
    name = f"/ecs/{ctx.unique_name(f'sim2real-lg-{suffix}-')}"
    logs.create_log_group(logGroupName=name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
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
    """RunTask, bounded-retrying past two transient windows: ECS placement failures
    (returned in the response body) and IAM/STS cross-service trust-policy propagation
    for a just-created execution role (raised as a ClientException, since ECS refuses
    to even schedule the task until it can assume the role)."""
    ecs = ctx.client("ecs")
    last_failures = None
    deadline = time.monotonic() + timeout_s
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
        except ecs.exceptions.ClientException as e:
            if "unable to assume the role" not in str(e):
                raise
            last_failures = str(e)
            time.sleep(3)
            continue
        if resp.get("tasks"):
            return resp["tasks"][0]["taskArn"]
        last_failures = resp.get("failures")
        time.sleep(5)
    raise AssertionError(f"run_task never scheduled a task within {timeout_s}s; failures={last_failures}")


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
