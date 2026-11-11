"""execute-command-on-stopped-task-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-on-stopped-task-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand succeeds against a RUNNING task with exec enabled, but is
    rejected once that same task has transitioned to STOPPED -- a wrong
    lifecycle-state rejection distinct from the exec-not-enabled case."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_network(ctx)
    task_role_arn = _create_ecs_exec_task_role(ctx)

    cluster_name = ctx.unique_name("sim2real-execstate-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-execstate-td-")
    taskdef = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "900"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=taskdef))
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[taskdef]))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    task_arn = _run_task_with_retry(ecs, cluster_arn, taskdef, net_cfg)
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn))

    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda status: status == "RUNNING",
        timeout_s=180,
        interval_s=5,
        description="task to reach RUNNING",
    )

    # Positive control: exec against the RUNNING task succeeds once the
    # managed exec agent has attached (this takes a little while after the
    # task itself reports RUNNING).
    session = _poll_until(
        lambda: _try_execute_command(ecs, cluster_arn, task_arn),
        lambda result: result is not None,
        timeout_s=120,
        interval_s=5,
        description="ExecuteCommand to succeed on the RUNNING task",
    )
    assert session["session"]["streamUrl"], "ExecuteCommand succeeded but returned no stream URL"

    # Now stop the task and let it reach STOPPED.
    ecs.stop_task(cluster=cluster_arn, task=task_arn)
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda status: status == "STOPPED",
        timeout_s=180,
        interval_s=5,
        description="task to reach STOPPED",
    )

    # Negative: exec against the now-STOPPED task is rejected.
    code, message = _error(
        lambda: ecs.execute_command(
            cluster=cluster_arn, task=task_arn, container="app", command="/bin/sh", interactive=True
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert message == "The execute command failed because execute command was not enabled when the task was run or the execute command agent isn't running. Wait and try again or run a new task with execute command enabled and try again.", f"unexpected message: {message!r}"

    # Effect absent: the task's state was not perturbed by the failed exec attempt.
    final_status = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"]
    assert final_status == "STOPPED", f"task state changed after rejected exec attempt: {final_status}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call AWS refuses must fail as an unexpected success, not as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _try_execute_command(ecs, cluster_arn, task_arn):
    """The managed exec agent needs a little while to attach after the task
    itself reports RUNNING; ECS reports this readiness gap with varying
    error codes/messages (TargetNotConnectedException, or a transient
    InvalidParameterException while the SSM channel isn't up yet). Treat any
    ClientError as "not ready yet" here -- the caller's bounded poll timeout
    is what turns a genuine, permanent misconfiguration into a clear
    "timed out" failure rather than a cryptic one-off exception.
    """
    try:
        return ecs.execute_command(
            cluster=cluster_arn, task=task_arn, container="app", command="/bin/sh", interactive=True
        )
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description} (last value: {result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _run_task_with_retry(ecs, cluster_arn, taskdef, net_cfg, attempts=4, delay_s=10):
    last_err = None
    for _ in range(attempts):
        try:
            resp = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=taskdef,
                launchType="FARGATE",
                networkConfiguration=net_cfg,
                enableExecuteCommand=True,
                count=1,
            )
            if resp["failures"]:
                last_err = AssertionError(f"RunTask reported failures: {resp['failures']}")
            else:
                return resp["tasks"][0]["taskArn"]
        except ClientError as err:
            last_err = err
        time.sleep(delay_s)
    raise AssertionError(f"RunTask never succeeded (likely IAM role propagation delay): {last_err}")


def _create_ecs_exec_task_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsexec-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-ecsexec-policy"
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a Fargate task")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available to launch a Fargate task")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]



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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
