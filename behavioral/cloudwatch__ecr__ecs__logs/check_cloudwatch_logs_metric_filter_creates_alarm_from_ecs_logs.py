"""cloudwatch-logs-metric-filter-creates-alarm-from-ecs-logs."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-logs-metric-filter-creates-alarm-from-ecs-logs"
GROUP = "log-metrics"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Logs metric filter on an ECS task's log group derives a metric that drives a real alarm."""
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    subnet_id, sg_id = _default_network(ctx)
    exec_role_arn = _create_ecs_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    log_group = ctx.unique_name("/sim2real/behav-ecs-logmf-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    token = ctx.unique_name("BEHAV-TOKEN-").upper().replace("-", "_")
    filter_name = ctx.unique_name("sim2real-behav-mf-")
    metric_name = ctx.unique_name("sim2real-behav-metric-")
    namespace = "Sim2RealBehavioral"
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern=f'"{token}"',
        metricTransformations=[
            {"metricName": metric_name, "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.5,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    family = ctx.unique_name("sim2real-behav-td-")
    reg = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        tags=[{"key": "sim2real", "value": "true"}],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                # The token repeats every 2 s for a bounded span, so whichever 60 s period the
                # alarm evaluates while the task runs holds a matching line.
                "command": ["sh", "-c", f"for i in $(seq 1 300); do echo {token}; sleep 2; done"],
                "essential": True,
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
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    task_arn = _run_task_with_iam_retry(
        ctx,
        ecs,
        cluster_name,
        task_def_arn,
        {
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(lambda: _stop_task(ecs, cluster_name, task_arn))

    points = _wait_metric_datapoints(ctx, namespace, metric_name, [], timeout_s=_budget_s(ctx, 300))
    if not points and _budget_spent(ctx):
        raise TimeoutError(f"a {namespace}/{metric_name} datapoint for the matched ECS log line: the run budget "
                           "ended first; not graded")
    assert points, "metric filter never produced a datapoint for the matched ECS log line"
    assert sum(p["Sum"] for p in points) >= 1, "metric filter derived metric never incremented"

    final_state = _poll_alarm_state(ctx, alarm_name, "ALARM", timeout_s=_budget_s(ctx, 240))
    if final_state != "ALARM" and _budget_spent(ctx):
        raise TimeoutError(f"alarm {alarm_name} reaching ALARM: the run budget ended first; not graded")
    assert final_state == "ALARM", (
        f"alarm never transitioned to ALARM from the log-derived metric, saw {final_state!r}"
    )


# ===== helpers =====
_POLL_S = 2.0
_IAM_RETRY_S = 64.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _stop_task(ecs, cluster_name: str, task_arn: str) -> None:
    """Stop the token-emitting task; one already stopped or gone is fine."""
    try:
        ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real teardown")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ClusterNotFoundException":
            return
        if code != "InvalidParameterException":
            raise
        # ECS answers InvalidParameterException for a task it no longer tracks; confirm it is gone.
        resp = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])
        live = [t for t in resp.get("tasks", []) if t.get("lastStatus") not in ("STOPPED", "DEPROVISIONING", "STOPPING")]
        if live:
            raise RuntimeError(f"task {task_arn} was not stopped: {live[0].get('lastStatus')}") from exc


def _default_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch the ECS task into")
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


def _create_ecs_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-ecsexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _run_task_with_iam_retry(
    ctx, ecs, cluster_name: str, task_def_arn: str, network_configuration: dict[str, Any],
    delay_s: float = _POLL_S,
) -> str:
    """RunTask can reject a just-created execution role with ClientException("...unable to
    assume the role...") until IAM trust propagates; retry that specific, transient rejection
    on a bound instead of sleeping blind before the first attempt."""
    last_error: Exception | None = None
    deadline = time.monotonic() + _budget_s(ctx, _IAM_RETRY_S)
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=network_configuration,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or "assume the role" not in str(exc):
                raise
            last_error = exc
        else:
            if resp.get("tasks"):
                return resp["tasks"][0]["taskArn"]
            last_error = AssertionError(f"RunTask placed no task: failures={resp.get('failures')}")
        if time.monotonic() + delay_s >= deadline:
            break
        time.sleep(delay_s)
    if _budget_spent(ctx):
        raise TimeoutError("RunTask succeeding after IAM propagation: the run budget ended first; not graded")
    raise AssertionError(f"RunTask never succeeded after IAM-propagation retries: {last_error}")


def _wait_metric_datapoints(
    ctx, namespace: str, metric_name: str, dimensions: list[dict[str, str]], timeout_s: float
) -> list[dict[str, Any]]:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=20)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum"],
        )
        points = resp.get("Datapoints", [])
        if points:
            return points
        time.sleep(_POLL_S)
    return []


def _poll_alarm_state(ctx, alarm_name: str, expected: str, timeout_s: float) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last: str = ""
    while time.monotonic() < deadline:
        alarms: list[dict[str, Any]] = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
        last = alarms[0]["StateValue"]
        if last == expected:
            return last
        time.sleep(_POLL_S)
    return last



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
