"""ecs-task-state-change-event-delivered-to-eventbridge-rule."""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-task-state-change-event-delivered-to-eventbridge-rule"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real ECS Fargate task's RUNNING then STOPPED transitions are delivered, in
    chronological order, as ECS Task State Change events to an EventBridge rule
    targeting an SQS queue."""
    ecs = ctx.client("ecs")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    _, subnet_id, sg_id = _default_vpc_subnet_sg(ctx)
    exec_role_arn = _create_ecs_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-ecscl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real:managed", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_arn))

    family = ctx.unique_name("sim2real-ecstd-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "20"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-ecsq-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-ecsrule-")
    pattern = {
        "source": ["aws.ecs"],
        "detail-type": ["ECS Task State Change"],
        "detail": {"clusterArn": [cluster_arn]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]

    def _cleanup_rule() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            events.delete_rule(Name=rule_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_rule)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    run_resp = _run_task_with_retry(
        ecs,
        cluster=cluster_arn,
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
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _cleanup_task() -> None:
        # The cluster teardown waits for the task to reach STOPPED.
        try:
            ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="check cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_task)

    seen = _collect_task_events(sqs, queue_url, task_arn, timeout_s=240.0)
    assert "RUNNING" in seen, f"no RUNNING event delivered; saw statuses {list(seen)}"
    assert "STOPPED" in seen, f"no STOPPED event delivered; saw statuses {list(seen)}"
    running_time = _parse_time(seen["RUNNING"]["time"])
    stopped_time = _parse_time(seen["STOPPED"]["time"])
    assert running_time <= stopped_time, "RUNNING event was not delivered before STOPPED event"

    stopped_envelope = seen["STOPPED"]
    assert stopped_envelope["source"] == "aws.ecs", (
        f"expected event source aws.ecs, got {stopped_envelope['source']!r}"
    )
    assert stopped_envelope["detail"]["clusterArn"] == cluster_arn, (
        f"expected detail.clusterArn {cluster_arn!r}, got "
        f"{stopped_envelope['detail'].get('clusterArn')!r}"
    )
    assert stopped_envelope["detail"]["desiredStatus"] == "STOPPED", (
        f"expected STOPPED event's desiredStatus to be STOPPED, got "
        f"{stopped_envelope['detail'].get('desiredStatus')!r}"
    )

    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert described["lastStatus"] == "STOPPED", (
        f"ECS's own record disagrees with the delivered event: describe_tasks reports "
        f"lastStatus={described['lastStatus']!r}"
    )


def _default_vpc_subnet_sg(ctx) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to attach an ENI to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "map-public-ip-on-launch", "Values": ["true"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no public subnet to launch a Fargate task into")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return vpc_id, subnet_id, sgs[0]["GroupId"]


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ecsxrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _run_task_with_retry(ecs, *, max_attempts=6, **kwargs):
    """Retries the real RunTask call on ClientError, which also absorbs the fresh
    execution role's IAM trust-propagation delay: a role ECS cannot yet assume surfaces
    here as a ClientError, not as a separate settle before this call."""
    from botocore.exceptions import ClientError

    last_exc: Exception | None = None
    for _ in range(max_attempts):
        try:
            return ecs.run_task(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _collect_task_events(sqs, queue_url, task_arn, timeout_s=240.0) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not {"RUNNING", "STOPPED"} <= set(seen):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if not envelope:
                continue
            detail = envelope.get("detail", {})
            if detail.get("taskArn") != task_arn:
                continue
            status = detail.get("lastStatus")
            if status:
                seen[status] = envelope
    return seen


def _parse_time(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _delete_cluster(ctx, cluster_arn: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)



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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
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
