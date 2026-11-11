"""ecs-service-action-event-triggers-target-lambda."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ecs-service-action-event-triggers-target-lambda"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_SIM2REAL_TAGS_KV = [{"key": "sim2real", "value": CHECK}]

_LAMBDA_CODE = (
    "def lambda_handler(event, context):\n"
    "    detail = event.get('detail', {})\n"
    "    print('ECS-SERVICE-ACTION-EVENT eventName=' + str(detail.get('eventName')))\n"
    "    return {'ok': True}\n"
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ECS service reaching steady state emits an "ECS Service Action" event
    (eventName SERVICE_STEADY_STATE) that an EventBridge rule routes to, and
    successfully invokes, a target Lambda function."""
    ecs = ctx.client("ecs")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    subnets, sg_id = _fargate_network(ctx)
    exec_role_arn = _create_ecs_execution_role(ctx)
    lambda_role_arn = _create_lambda_basic_role(ctx)

    cluster_name = ctx.unique_name("sim2real-ecscl2-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_SIM2REAL_TAGS_KV)[
        "cluster"
    ]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_arn))

    family = ctx.unique_name("sim2real-ecstd2-")
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
                "command": ["sleep", "3600"],
                "essential": True,
            }
        ],
        tags=_SIM2REAL_TAGS_KV,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    fn_name = ctx.unique_name("sim2real-ecssvcfn-")
    fn_arn = _create_lambda_function(ctx, fn_name, lambda_role_arn)

    rule_name = ctx.unique_name("sim2real-ecssvcrule-")
    pattern = {
        "source": ["aws.ecs"],
        "detail-type": ["ECS Service Action"],
        "detail": {"clusterArn": [cluster_arn], "eventName": ["SERVICE_STEADY_STATE"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": fn_arn}])

    service_name = ctx.unique_name("sim2real-ecssvc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=_SIM2REAL_TAGS_KV,
    )
    ctx.on_cleanup(lambda: _delete_service(ctx, cluster_arn, service_name))

    log_group = f"/aws/lambda/{fn_name}"
    matches = _poll_until(
        lambda: _find_log_matches(logs, log_group, "SERVICE_STEADY_STATE"),
        lambda m: len(m) > 0,
        timeout_s=300,
        interval_s=10.0,
        description=f"Lambda {fn_name} invoked with an ECS SERVICE_STEADY_STATE event",
    )
    assert any("SERVICE_STEADY_STATE" in m for m in matches), (
        f"expected the target Lambda's own logs to contain 'SERVICE_STEADY_STATE', got {matches!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ecsxrole2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    # No unconditional wait for IAM propagation here: the role is not touched again
    # until the Fargate task actually launches, several ECS/Lambda/EventBridge API
    # calls later, and ECS's own service scheduler retries task placement until the
    # role is assumable -- absorbed by the bounded steady-state poll below.
    return role_arn


def _create_lambda_basic_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
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
    # No unconditional wait here either: _create_lambda_function's own retry loop
    # (below) is the bounded retry that absorbs IAM propagation for CreateFunction.
    return role_arn


def _create_lambda_function(ctx, fn_name: str, role_arn: str) -> str:
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", _LAMBDA_CODE)
    code_bytes = buf.getvalue()

    fn_arn = None
    last_exc: Exception | None = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": code_bytes},
                Timeout=30,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    if fn_arn is None:
        raise last_exc
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3.0,
        description="Lambda function Active",
    )
    return fn_arn


def _find_log_matches(logs, log_group: str, needle: str) -> list[str]:
    try:
        resp = logs.filter_log_events(
            logGroupName=log_group, filterPattern=f'"{needle}"'
        )
    except logs.exceptions.ResourceNotFoundException:
        return []
    return [e["message"] for e in resp.get("events", [])]


def _delete_service(ctx, cluster_arn: str, service_name: str) -> None:
    ecs = ctx.client("ecs")
    # The cluster teardown waits for the service's tasks to reach STOPPED.
    try:
        ecs.update_service(cluster=cluster_arn, service=service_name, desiredCount=0)
        ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
    except ClientError as exc:
        gone = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")
        if exc.response["Error"]["Code"] not in gone:
            raise


def _delete_cluster(ctx, cluster_arn: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
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
