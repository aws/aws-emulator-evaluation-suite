"""deploy-stack-fails-without-log-group-resource-policy."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-fails-without-log-group-resource-policy"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task whose execution role has no CloudWatch Logs permissions stops with
    ResourceInitializationError and creates no log stream, while the same task with the standard
    execution policy delivers its log line."""
    ecs = ctx.client("ecs")
    logs_client = ctx.client("logs")
    iam = ctx.client("iam")
    net = _get_network(ctx)

    cluster_name = ecs.create_cluster(clusterName=_xname(ctx, "cluster"), tags=_ecs_tags_kv())[
        "cluster"
    ]["clusterName"]
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(ecs, cluster_name))

    log_group_name = _xname(ctx, "lg")
    logs_client.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs_client.delete_log_group(logGroupName=log_group_name))

    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }

    role_no_logs = _create_role(ctx, iam, trust_doc, managed_policy_arn=None)
    role_with_logs = _create_role(
        ctx,
        iam,
        trust_doc,
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    net_config = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    negative_stop_reason = _run_task_and_get_stop_reason(
        ctx, ecs, cluster_name, role_no_logs["arn"], log_group_name, net_config, "neg"
    )
    assert "ResourceInitializationError" in negative_stop_reason, (
        f"execution role with no logs permissions should stop with ResourceInitializationError, "
        f"got stop reason {negative_stop_reason!r}"
    )
    neg_streams = logs_client.describe_log_streams(logGroupName=log_group_name).get("logStreams", [])
    neg_stream_names = {s["logStreamName"] for s in neg_streams}
    assert not any("neg" in n for n in neg_stream_names), (
        f"role without logs permissions should never have created a log stream, found {neg_stream_names}"
    )

    positive_stop_reason = _run_task_and_get_stop_reason(
        ctx, ecs, cluster_name, role_with_logs["arn"], log_group_name, net_config, "pos"
    )
    assert "ResourceInitializationError" not in positive_stop_reason, (
        f"execution role with the standard ECS execution policy should never hit "
        f"ResourceInitializationError, got stop reason {positive_stop_reason!r}"
    )

    def _pos_events():
        streams = logs_client.describe_log_streams(
            logGroupName=log_group_name, logStreamNamePrefix="pos"
        ).get("logStreams", [])
        for s in streams:
            events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=s["logStreamName"], limit=5
            ).get("events", [])
            if events:
                return events
        return []

    pos_events = _poll_until(
        _pos_events, lambda evs: len(evs) > 0, timeout_s=60.0, interval_s=5.0,
        description="log events from role-with-permissions task",
    )
    assert any("sim2real-positive-control" in e["message"] for e in pos_events), (
        f"expected a delivered log event containing the positive-control marker, got {pos_events!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    """ECS resource tags use lowercase key/value fields, unlike EC2/CFN's Key/Value."""
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _get_network(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; this check relies on the shared network's "
            "public shared-network subnets for the Fargate task's awsvpc networking and does not "
            "provision a custom VPC/IGW/route-table stack to stay lean"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no shared-network subnet available")
    subnet_id = subnets[0]["SubnetId"]
    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg"),
        Description="sim2real behavioral check SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _xsvc_tags_kv()}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _delete_sg_with_retry(ec2, sg_id: str, attempts: int = 8) -> None:
    for i in range(attempts):
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or i == attempts - 1:
                raise
            time.sleep(10.0)


def _delete_cluster_with_retry(ecs, cluster_name: str, attempts: int = 8) -> None:
    """A task's own describe_tasks status reaches STOPPED slightly before ECS's cluster-level
    bookkeeping stops counting it as active, so an immediate delete_cluster can transiently see
    ClusterContainsTasksException even though every task this check ran is already stopped."""
    for i in range(attempts):
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] not in {
                "ClusterContainsTasksException",
                "ClusterContainsContainerInstancesException",
            } or i == attempts - 1:
                raise
            time.sleep(10.0)


def _create_role(ctx, iam, trust_doc: dict[str, Any], managed_policy_arn: str | None) -> dict[str, str]:
    import json as _json

    name = _xname(ctx, "role")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_json.dumps(trust_doc))["Role"]

    def _cleanup():
        if managed_policy_arn:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=managed_policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    if managed_policy_arn:
        iam.attach_role_policy(RoleName=name, PolicyArn=managed_policy_arn)
    return {"name": name, "arn": role["Arn"]}


def _run_task_retrying_role_propagation(ecs, cluster_name: str, task_def_arn: str, net_config: dict) -> str:
    """RunTask can synchronously reject a just-created execution role -- 'ECS was unable to assume
    the role' -- until the role's trust policy has propagated to STS everywhere. That rejection
    surfaces here, at the RunTask call itself, never in the task's own lifecycle; the permission
    denial this check exists to observe is a completely different, later failure surface (an
    async ResourceInitializationError read back via describe_tasks). So retrying ONLY this specific,
    pre-task-start rejection cannot mask the thing under test -- it waits for exactly the
    asynchrony it names, and nothing else."""
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            run_resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                networkConfiguration=net_config,
                count=1,
            )
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if "assume" not in msg.lower():
                raise
            last = msg
            time.sleep(5.0)
            continue
        failures = run_resp.get("failures") or []
        if failures and all("assume" in f.get("reason", "").lower() for f in failures):
            last = failures
            time.sleep(5.0)
            continue
        if failures:
            raise AssertionError(f"RunTask itself failed: {failures}")
        return run_resp["tasks"][0]["taskArn"]
    raise AssertionError(
        f"RunTask kept rejecting execution role {task_def_arn} as unassumable for 90s "
        f"(IAM-to-STS role propagation never completed): {last!r}"
    )


def _run_task_and_get_stop_reason(
    ctx, ecs, cluster_name: str, execution_role_arn: str, log_group_name: str, net_config: dict, prefix: str
) -> str:
    family = _xname(ctx, f"task-{prefix}")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["/bin/sh", "-c", "echo sim2real-positive-control; sleep 30"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group_name,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": prefix,
                    },
                },
            }
        ],
    )["taskDefinition"]
    task_def_arn = task_def["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    task_arn = _run_task_retrying_role_propagation(ecs, cluster_name, task_def_arn, net_config)
    ctx.on_cleanup(lambda: _stop_task_ignore_errors(ecs, cluster_name, task_arn))

    def _task_state():
        resp = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])
        return resp["tasks"][0]

    task = _poll_until(
        _task_state,
        lambda t: t["lastStatus"] in {"STOPPED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"task {prefix} reaching STOPPED",
    )
    container = task["containers"][0]
    return container.get("reason") or task.get("stoppedReason") or ""


def _stop_task_ignore_errors(ecs, cluster_name: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


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
            except ClientError:
                pass
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
