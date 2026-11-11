"""execute-command-rejected-without-ssm-connection."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-rejected-without-ssm-connection"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand on an exec-enabled RUNNING task whose role lacks ssmmessages permissions is
    rejected with InvalidParameterException (not TargetNotConnectedException): its exec agent never
    reaches RUNNING, before or after the rejected call."""
    ecs = ctx.client("ecs")
    setup = _exec_task_setup(ctx)
    cluster, task_arn, container_name = setup["cluster"], setup["task_arn"], setup["container_name"]

    # A PENDING task yields the same InvalidParameterException for the wrong reason, so wait
    # (bounded) for RUNNING to attribute the rejection to the missing ssmmessages permissions.
    task = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        task = _describe_task(ecs, cluster, task_arn)
        if task["lastStatus"] in ("RUNNING", "STOPPED"):
            break
        time.sleep(3)
    assert task is not None and task["lastStatus"] == "RUNNING", (
        f"task never reached RUNNING within the poll budget: {task['lastStatus'] if task else None}"
    )

    # Wait (bounded) for the ExecuteCommandAgent record to appear; without ssmmessages
    # permissions it can never connect, so it must not reach RUNNING.
    exec_agents = []
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        task = _describe_task(ecs, cluster, task_arn)
        containers = task.get("containers", [])
        container = next((c for c in containers if c["name"] == container_name), None)
        exec_agents = [
            a
            for a in (container.get("managedAgents", []) if container else [])
            if a["name"] == "ExecuteCommandAgent"
        ]
        if exec_agents:
            break
        time.sleep(2)
    already_running = any(a.get("lastStatus") == "RUNNING" for a in exec_agents)
    assert not already_running, "exec agent connected despite lacking ssmmessages permissions"

    error = _error(
        lambda: ecs.execute_command(
            cluster=cluster,
            task=task_arn,
            container=container_name,
            command="/bin/sh",
            interactive=True,
        )
    )
    assert error == _EXEC_NOT_AVAILABLE, f"expected {_EXEC_NOT_AVAILABLE!r}, got {error!r}"

    # The rejection must not have left a connected exec agent behind.
    task2 = _describe_task(ecs, cluster, task_arn)
    container2 = next((c for c in task2.get("containers", []) if c["name"] == container_name), None)
    exec_agents2 = [
        a for a in (container2.get("managedAgents", []) if container2 else []) if a["name"] == "ExecuteCommandAgent"
    ]
    running2 = [a for a in exec_agents2 if a.get("lastStatus") == "RUNNING"]
    assert not running2, f"expected no RUNNING exec managed agent after rejection, got {running2}"


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)



def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _default_vpc_subnet_and_sg(ctx):

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
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _create_role(ctx, prefix, trust_service, policy_arns=(), inline_policies=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": "execute-command-rejected-without-ssm-connection"}],
    )["Role"]["Arn"]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    for name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=name, PolicyDocument=json.dumps(doc))

    def _cleanup():
        for name in (inline_policies or {}):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _exec_task_setup(ctx):
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_vpc_subnet_and_sg(ctx)

    exec_role_arn = _create_role(
        ctx,
        "sim2real-ecsx-exrole-",
        "ecs-tasks.amazonaws.com",
        policy_arns=["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
    )
    # Deliberately NO ssmmessages permissions: the exec agent opens its SSM channel with the task
    # role, so it never reaches RUNNING. TargetNotConnectedException is reserved for an agent that
    # reached RUNNING and then lost connectivity.
    task_role_arn = _create_role(
        ctx,
        "sim2real-ecsx-taskrole-",
        "ecs-tasks.amazonaws.com",
    )

    check_tags = [{"key": "sim2real-check", "value": "execute-command-rejected-without-ssm-connection"}]

    cluster_name = ctx.unique_name("sim2real-ecsx-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=check_tags)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecsx-taskdef-")
    container_name = "app"
    reg = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "600"],
            }
        ],
        tags=check_tags,
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    tasks = []
    last_failures = None
    last_error = None
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, max(1.0, left - 5.0)))
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                platformVersion="LATEST",
                count=1,
                enableExecuteCommand=True,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
                tags=check_tags,
            )
        except ClientError as exc:
            # A just-created IAM role is eventually consistent; ECS can briefly fail to assume it.
            last_error = exc
            if exc.response["Error"]["Code"] == "ClientException" and "unable to assume the role" in str(exc):
                time.sleep(2)
                continue
            raise
        tasks = resp.get("tasks", [])
        if tasks:
            break
        last_failures = resp.get("failures")
        time.sleep(2)
    if not tasks:
        raise AssertionError(f"RunTask never placed a task: failures={last_failures} last_error={last_error}")
    task = tasks[0]
    task_arn = task["taskArn"]

    def _stop_and_wait():
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
            if not d or d[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_stop_and_wait)

    return {"cluster": cluster_name, "task_arn": task_arn, "container_name": container_name}



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.
    DeleteCluster is refused while services, tasks or container instances remain, and a running
    task's ENI keeps the network from being deleted."""
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


def _describe_task(ecs, cluster, task_arn, timeout_s=60.0):
    """DescribeTasks for one task, retrying while ECS does not list it yet: right after RunTask
    the task can briefly appear under `failures` (reason MISSING) instead of `tasks`."""
    deadline = time.monotonic() + timeout_s
    while True:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        if tasks:
            return tasks[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"DescribeTasks never listed task {task_arn} within {timeout_s}s")
        time.sleep(2)


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
