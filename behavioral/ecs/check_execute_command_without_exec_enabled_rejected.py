"""execute-command-without-exec-enabled-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-without-exec-enabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand against a RUNNING Fargate task launched without enableExecuteCommand is
    rejected with InvalidParameterException before ECS attempts an SSM connection; the identical
    call on the same task definition, launched with the flag set, must stop failing that way.
    """
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_network(ctx)
    task_role_arn = _create_exec_task_role(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    net_cfg = {
        "awsvpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
    }

    # --- Negative: launched WITHOUT enableExecuteCommand ---
    task_arn = _run_task(ctx, ecs, cluster_arn, td_arn, net_cfg, enable=False)
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="test-cleanup"))

    described = _wait_running(ctx, ecs, cluster_arn, task_arn)
    assert described["enableExecuteCommand"] is False, "task was unexpectedly created with execute-command enabled"

    error = _error(
        lambda: ecs.execute_command(
            cluster=cluster_arn, task=task_arn, container="app", command="/bin/sh", interactive=True
        )
    )
    assert error == _EXEC_NOT_AVAILABLE, (
        f"expected {_EXEC_NOT_AVAILABLE!r} (execute-command not enabled at launch), got {error!r}"
    )

    # Effect absent: no exec channel was opened -- the flag is still False and no
    # ExecuteCommandAgent record was ever created for this task.
    still = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert still["enableExecuteCommand"] is False, "enableExecuteCommand flipped True after a rejected ExecuteCommand call"
    stray_agents = [
        a for c in still.get("containers", []) for a in c.get("managedAgents", []) if a["name"] == "ExecuteCommandAgent"
    ]
    assert not stray_agents, f"unexpected ExecuteCommandAgent record on a task launched without the flag: {stray_agents}"

    # --- Positive control: the SAME task definition, launched WITH enableExecuteCommand ---
    task2_arn = _run_task(ctx, ecs, cluster_arn, td_arn, net_cfg, enable=True)
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=task2_arn, reason="test-cleanup"))

    described2 = _wait_running(ctx, ecs, cluster_arn, task2_arn)
    assert described2["enableExecuteCommand"] is True, "positive-control task must report enableExecuteCommand=True"

    # The managed exec agent needs a moment to register with SSM after the task reaches
    # RUNNING; a call in that window can still see InvalidParameterException for a reason
    # unrelated to the flag. Retry (bounded) past that transient rather
    # than accepting a single reading as proof the flag failed to clear the launch-time gate.
    error2 = _SUCCEEDED
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        error2 = _error(
            lambda: ecs.execute_command(
                cluster=cluster_arn, task=task2_arn, container="app", command="/bin/sh", interactive=True
            )
        )
        if error2[0] != "InvalidParameterException":
            break
        time.sleep(5)
    assert error2[0] != "InvalidParameterException", (
        "enabling the flag must clear the launch-time gate; still got InvalidParameterException "
        "on the identical call after enabling it"
    )
    assert error2 == _SUCCEEDED or error2[0] == "TargetNotConnectedException", (
        f"expected either success or TargetNotConnectedException once the flag is enabled, got {error2!r}"
    )


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _create_exec_task_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-execrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = "ecs-exec-ssmmessages"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ssmmessages:CreateControlChannel",
                            "ssmmessages:CreateDataChannel",
                            "ssmmessages:OpenControlChannel",
                            "ssmmessages:OpenDataChannel",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _run_task(ctx, ecs, cluster_arn: str, td_arn: str, net_cfg: dict, *, enable: bool) -> str:
    # Freshly-created IAM roles are eventually consistent -- ECS can transiently fail to
    # assume the just-created task role for a short window after CreateRole/PutRolePolicy.
    # Retry rather than treat that as a real RunTask rejection.
    deadline = time.monotonic() + 60
    last_error: Any = None
    while time.monotonic() < deadline:
        try:
            run_resp = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                enableExecuteCommand=enable,
                networkConfiguration=net_cfg,
            )
        except ClientError as exc:
            last_error = exc
            if "assume" in str(exc).lower():
                time.sleep(5)
                continue
            raise
        if run_resp.get("failures"):
            last_error = run_resp["failures"]
            time.sleep(5)
            continue
        if run_resp.get("tasks"):
            return run_resp["tasks"][0]["taskArn"]
        last_error = "RunTask returned neither tasks nor failures"
        time.sleep(5)
    raise AssertionError(f"RunTask never placed a task (enableExecuteCommand={enable}): {last_error}")


def _wait_running(ctx, ecs, cluster_arn: str, task_arn: str) -> dict:
    try:
        return _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
            lambda t: t["lastStatus"] == "RUNNING",
            timeout_s=120,
            interval_s=3,
        )
    except AssertionError:
        raise AssertionError(
            "task never reached RUNNING (likely no image-pull egress in this environment)",
        )


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# What _error returns for a call that succeeds; no AWS error code can equal it.
_SUCCEEDED = ("<succeeded>", None)


def _error(fn):
    """Call fn(); return its botocore (code, message), or _SUCCEEDED when it succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return _SUCCEEDED


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
                if exc.response["Error"]["Code"] != "ServiceNotFoundException":
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
