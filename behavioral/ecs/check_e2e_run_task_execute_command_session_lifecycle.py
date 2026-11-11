"""e2e-run-task-execute-command-session-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-run-task-execute-command-session-lifecycle"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask with enableExecuteCommand opens a real SSM session visible via
    DescribeSessions, and StopTask ends that session."""
    ecs = ctx.client("ecs")

    ssm = ctx.client("ssm")

    role_arn = _create_exec_task_role(ctx)
    net = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-exec-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-exec-td-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        taskRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "3600"],
                "essential": True,
            }
        ],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = _run_task_with_role_retry(
        ecs,
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        enableExecuteCommand=True,
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnet_ids"][:1],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_and_wait() -> None:
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="check cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]["lastStatus"],
            lambda s: s == "STOPPED",
            timeout_s=180,
            interval_s=5,
        )

    ctx.on_cleanup(_stop_and_wait)

    def _agent_status():
        d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]
        for c in d.get("containers", []):
            for agent in c.get("managedAgents", []):
                if agent["name"] == "ExecuteCommandAgent":
                    return agent["lastStatus"]
        return None

    agent_status = _poll_until(_agent_status, lambda s: s == "RUNNING", timeout_s=300, interval_s=10)
    assert agent_status == "RUNNING"

    exec_resp = ecs.execute_command(
        cluster=cluster_name,
        task=task_arn,
        container="main",
        command="echo sim2real-exec-check",
        interactive=True,
    )
    session_id = exec_resp["session"]["sessionId"]
    assert session_id

    sessions = ssm.describe_sessions(
        State="Active", Filters=[{"key": "SessionId", "value": session_id}]
    )["Sessions"]
    assert len(sessions) == 1
    assert sessions[0]["SessionId"] == session_id

    ecs.stop_task(cluster=cluster_name, task=task_arn, reason="ending exec session")

    def _active_session_count() -> int:
        return len(
            ssm.describe_sessions(
                State="Active", Filters=[{"key": "SessionId", "value": session_id}]
            )["Sessions"]
        )

    remaining = _poll_until(_active_session_count, lambda n: n == 0, timeout_s=180, interval_s=5)
    assert remaining == 0


def _run_task_with_role_retry(ecs, timeout_s=60.0, **kwargs):
    """IAM roles are eventually consistent; retry RunTask while ECS can't yet assume the
    task role we just created/attached ("ECS was unable to assume the role ...")."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.run_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if code == "ClientException" and "ssume" in msg.lower():
                time.sleep(5)
                continue
            raise
    raise last_err if last_err is not None else RuntimeError("RunTask never succeeded")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    assert subnet_ids, f"no subnets found in vpc {vpc_id}"
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    assert sgs, f"no default security group found in vpc {vpc_id}"
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _delete_cluster_retry(ecs, cluster_name, timeout_s=90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterContainsTasksException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_exec_task_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "ecs-exec-ssmmessages"
    policy_doc = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]



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
