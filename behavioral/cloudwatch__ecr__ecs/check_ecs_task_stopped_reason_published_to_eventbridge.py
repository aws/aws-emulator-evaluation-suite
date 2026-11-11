"""ecs-task-stopped-reason-published-to-eventbridge."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-stopped-reason-published-to-eventbridge"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The stoppedReason/stopCode/exitCode detail fields are propagated intact through the ECS Task State Change event."""
    ecs = ctx.client("ecs")
    role_arn = _create_ecs_execution_role(ctx)
    cluster_arn = _create_cluster(ctx)
    queue_url, queue_arn = _create_event_queue(ctx, ctx.unique_name("sim2real-ecs-reasonq-"))
    pattern = {
        "source": ["aws.ecs"],
        "detail-type": ["ECS Task State Change"],
        "detail": {"clusterArn": [cluster_arn], "lastStatus": ["STOPPED"]},
    }
    _wire_rule_to_queue(ctx, ctx.unique_name("sim2real-ecs-reason-rule-"), pattern, queue_url, queue_arn)

    # The essential container exits non-zero on its own, so ECS stops the task with a
    # deterministic, documented stoppedReason/stopCode ("Essential container in task exited").
    task_arn = _run_minimal_fargate_task(
        ctx, cluster_arn, ctx.unique_name("sim2real-ecs-reason-fam-"), ["/bin/sh", "-c", "exit 3"], role_arn
    )

    stopped = _poll_for_event(
        ctx,
        queue_url,
        lambda body: body.get("detail-type") == "ECS Task State Change" and body.get("detail", {}).get("taskArn") == task_arn,
        timeout_s=240,
    )
    assert stopped is not None, "no ECS Task State Change event delivered for the stopped task"
    detail = stopped["detail"]
    assert detail["lastStatus"] == "STOPPED"
    assert detail["stoppedReason"] == "Essential container in task exited"
    assert detail["stopCode"] == "EssentialContainerExited"
    container = next(c for c in detail["containers"] if c["name"] == "main")
    assert container["exitCode"] == 3

    # Cross-check the EventBridge detail against the ECS API's own record of the task.
    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert described["stoppedReason"] == "Essential container in task exited"
    described_container = next(c for c in described["containers"] if c["name"] == "main")
    assert described_container["exitCode"] == 3


# ===== helpers =====


def _create_event_queue(ctx: Any, name: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _wire_rule_to_queue(
    ctx: Any, rule_name: str, event_pattern: dict[str, Any], queue_url: str, queue_arn: str, target_id: str = "t1"
) -> str:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

    def _cleanup_targets() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=[target_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_targets)
    return rule_arn


def _poll_for_event(ctx: Any, queue_url: str, predicate, timeout_s: float, interval_s: int = 10):
    """Poll the queue until a message matching predicate arrives, or the full timeout elapses."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, min(interval_s, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    return None


def _create_ecs_execution_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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


def _create_cluster(ctx: Any) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    arn = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, arn))
    return arn


def _default_network_config(ctx: Any) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch an ECS Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch an ECS Fargate task into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [subnets[0]["SubnetId"]],
        "securityGroups": [sgs[0]["GroupId"]],
        "assignPublicIp": "ENABLED",
    }


def _run_minimal_fargate_task(ctx: Any, cluster_arn: str, family: str, command: list[str], exec_role_arn: str) -> str:
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)
    task_def_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command,
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    last_err: Any = None
    deadline = time.monotonic() + 90
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            run = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={"awsvpcConfiguration": net},
            )
            if run.get("failures"):
                last_err = run["failures"]
            else:
                return run["tasks"][0]["taskArn"]
        except ClientError as exc:  # a brand-new execution role is not assumable until IAM propagates
            if "assume the role" not in str(exc) and "AccessDenied" not in str(exc):
                raise
            last_err = exc
        if time.monotonic() >= deadline:
            raise AssertionError(f"RunTask never succeeded within 90 s: {last_err}")
        time.sleep(2)



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
