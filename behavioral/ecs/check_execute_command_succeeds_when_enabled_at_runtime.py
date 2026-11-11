"""execute-command-succeeds-when-enabled-at-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-succeeds-when-enabled-at-runtime"
GROUP = "server-side"
SERVICES = ["ecs"]

_ECS_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": "sim2real-ecsx-"},
]
_IAM_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecsx-"},
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand succeeds against a Fargate task once its ExecuteCommandAgent
    reports RUNNING, and the exact sessionId it hands back must show up in SSM's own
    DescribeSessions(State=Active) listing, so a target cannot pass by fabricating one."""
    ecs = ctx.client("ecs")
    ssm = ctx.client("ssm")
    setup = _exec_task_setup(ctx)
    cluster, cluster_arn, task_arn, container_name = (
        setup["cluster"],
        setup["cluster_arn"],
        setup["task_arn"],
        setup["container_name"],
    )

    deadline = time.monotonic() + 240
    running_container = None
    while time.monotonic() < deadline:
        task = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        if task["lastStatus"] == "STOPPED":
            raise AssertionError(f"task stopped before exec agent connected: {task.get('stoppedReason')}")
        containers = task.get("containers", [])
        container = next((c for c in containers if c["name"] == container_name), None)
        if container:
            agents = container.get("managedAgents", [])
            exec_agent = next((a for a in agents if a["name"] == "ExecuteCommandAgent"), None)
            if exec_agent and exec_agent.get("lastStatus") == "RUNNING":
                running_container = container
                break
        time.sleep(2)

    if running_container is None:
        raise AssertionError(
            "ExecuteCommandAgent never reached RUNNING within the poll budget",
        )

    resp = ecs.execute_command(
        cluster=cluster,
        task=task_arn,
        container=container_name,
        command="/bin/sh",
        interactive=True,
    )

    assert resp["clusterArn"] == cluster_arn, f"expected clusterArn {cluster_arn!r}, got {resp['clusterArn']!r}"
    assert resp["taskArn"] == task_arn, f"expected taskArn {task_arn!r}, got {resp['taskArn']!r}"
    assert resp["containerName"] == container_name, (
        f"expected containerName {container_name!r}, got {resp['containerName']!r}"
    )
    assert resp["interactive"] is True, f"expected interactive=True, got {resp['interactive']!r}"
    session = resp["session"]
    assert session["sessionId"], "expected a non-empty SSM session id"
    assert session["streamUrl"].startswith("wss://"), session["streamUrl"]
    assert session["tokenValue"], "expected a non-empty SSM session token"

    matched = _poll_for_ssm_session(ssm, session["sessionId"], timeout_s=30)
    assert matched is not None, (
        f"sessionId {session['sessionId']!r} returned by ExecuteCommand was never visible via "
        "ssm:DescribeSessions(State=Active) -- the session data was fabricated, not backed by a "
        "real SSM Session Manager session"
    )
    assert matched["SessionId"] == session["sessionId"], (
        f"expected the matched SSM session id to equal {session['sessionId']!r}, got {matched['SessionId']!r}"
    )
    assert matched.get("Target"), "matching SSM session has no Target identifier"


# ===== helpers =====

def _poll_for_ssm_session(ssm, session_id: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sessions = ssm.describe_sessions(State="Active").get("Sessions", [])
        for s in sessions:
            if s.get("SessionId") == session_id:
                return s
        time.sleep(interval_s)
    return None


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS
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
    task_role_arn = _create_role(
        ctx,
        "sim2real-ecsx-taskrole-",
        "ecs-tasks.amazonaws.com",
        inline_policies={
            "ecs-exec-ssmmessages": {
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
        },
    )

    cluster_name = ctx.unique_name("sim2real-ecsx-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
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
        tags=_ECS_TAGS,
        containerDefinitions=[
            {
                "name": container_name,
                "image": "public.ecr.aws/docker/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4",
                "essential": True,
                "command": ["sleep", "600"],
            }
        ],
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    tasks = []
    last_failures = None
    last_error = None
    # Freshly-created IAM roles are eventually consistent -- ECS can transiently fail to
    # assume the just-created execution/task role for a short window after
    # CreateRole/AttachRolePolicy. Retry on that specific rejection rather than treating
    # it as a real one, holding the same ~120s ceiling as the role-propagation window.
    run_deadline = time.monotonic() + 120
    while time.monotonic() < run_deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                platformVersion="LATEST",
                count=1,
                enableExecuteCommand=True,
                tags=_ECS_TAGS,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
            )
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] == "ClientException" and "unable to assume the role" in str(exc):
                time.sleep(3)
                continue
            raise
        tasks = resp.get("tasks", [])
        if tasks:
            break
        last_failures = resp.get("failures")
        time.sleep(3)
    if not tasks:
        raise AssertionError(f"RunTask never placed a task: failures={last_failures} last_error={last_error}")
    task = tasks[0]
    task_arn = task["taskArn"]
    assert task.get("enableExecuteCommand") is True, (
        f"expected RunTask to echo enableExecuteCommand=True, got {task.get('enableExecuteCommand')!r}"
    )

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

    return {
        "cluster": cluster_name,
        "cluster_arn": cluster_arn,
        "task_arn": task_arn,
        "container_name": container_name,
    }


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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ClusterNotFoundException"):
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
