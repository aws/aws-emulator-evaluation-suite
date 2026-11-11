"""ecs-task-execution-role-trusts-ecs-tasks-service."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "ecs-task-execution-role-trusts-ecs-tasks-service"
GROUP = "iam-trust"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role trusting ecs-tasks.amazonaws.com is assumed to run a Fargate task: the
    container exits cleanly and its awslogs output, pushed with that role, lands in the log stream."""
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")

    _, subnet_ids, sg_id = _default_vpc_info(ctx)

    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust_policy = {
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        )
    )

    log_group = ctx.unique_name("sim2real-ecs-exec-lg-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    cluster_name = ctx.unique_name("sim2real-ecs-exec-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-exec-task-")
    marker = f"hello-from-{family}"
    task_def_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "sim2real",
                    },
                },
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    netcfg = {
        "awsvpcConfiguration": {
            "subnets": subnet_ids[:1],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    task = _run_task_with_retry(ctx, ecs, cluster_name, family, netcfg)
    task_arn = task["taskArn"]

    def _cleanup_task():
        from botocore.exceptions import ClientError

        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="test-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_task)

    assert task["stopCode"] == "EssentialContainerExited", (
        f"expected the container to actually run (proving the execution role was "
        f"assumable), got stopCode={task.get('stopCode')!r} reason={task.get('stoppedReason')!r}"
    )
    container = task["containers"][0]
    assert container["exitCode"] == 0, f"container exited non-zero: {container}"

    events = _poll_until(
        lambda: logs.filter_log_events(
            logGroupName=log_group, logStreamNamePrefix="sim2real"
        )["events"],
        lambda evs: any(marker in e["message"] for e in evs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert any(marker in e["message"] for e in events), (
        f"expected log line {marker!r} pushed via the execution role, got {events}"
    )


def _default_vpc_info(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; needed to place an awsvpc-mode "
            "Fargate task with a public IP to pull a public image and push logs"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _run_task_with_retry(ctx, ecs, cluster_name, family, netcfg, window_s=6 * (180.0 + 15.0)):
    """RunTask right after creating an IAM role can transiently fail while the
    role's trust policy propagates to the ECS control plane. That can surface
    two ways: RunTask itself raises ClientException synchronously ("ECS was
    unable to assume the role..."), or RunTask accepts the task but it
    immediately stops with stopCode=TaskFailedToStart. Retry through both
    forms before concluding the role is genuinely not assumable."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (window_s if left is None else min(window_s, left - 5))
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=family,
                launchType="FARGATE",
                networkConfiguration=netcfg,
                count=1,
            )
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        assert not resp["failures"], f"RunTask returned failures: {resp['failures']}"
        task_arn = resp["tasks"][0]["taskArn"]
        last_task = _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0],
            lambda t: t["lastStatus"] == "STOPPED",
            timeout_s=180.0,
            interval_s=5.0,
        )
        if last_task["stopCode"] != "TaskFailedToStart" or time.monotonic() >= deadline:
            return last_task
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
