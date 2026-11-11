"""execute-command-without-enable-flag-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-without-enable-flag-rejected"
GROUP = "server-side"
SERVICES = ["ecs"]

_CONTAINER_NAME = "app"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand on a RUNNING task launched without enableExecuteCommand is rejected with
    InvalidParameterException, while an exec-enabled task with a connected agent is not."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    subnet_id = _default_subnet(ec2, ctx=ctx)
    if subnet_id is None:
        raise AssertionError("no shared network VPC subnet available in this account/region")

    task_role_arn = _create_ssm_task_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": _CONTAINER_NAME,
                "image": "public.ecr.aws/nginx/nginx:1.27",
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe_deregister_task_def(ecs, td_arn))

    def _run_and_wait_running(*, enable_execute_command: bool, task_role_arn: str | None = None) -> str:
        kwargs = dict(
            cluster=cluster_arn,
            taskDefinition=td_arn,
            launchType="FARGATE",
            platformVersion="LATEST",
            count=1,
            enableExecuteCommand=enable_execute_command,
            networkConfiguration={
                "awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}
            },
        )
        if task_role_arn is not None:
            kwargs["overrides"] = {"taskRoleArn": task_role_arn}

        # A just-created IAM role is eventually consistent -- ECS can transiently fail to
        # assume it for a short window after CreateRole/PutRolePolicy. Retry that specific
        # failure rather than treat it as a real rejection.
        deadline = time.monotonic() + 60.0
        run_resp = None
        while True:
            try:
                run_resp = ecs.run_task(**kwargs)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClientException" and "assume" in str(exc).lower() and time.monotonic() < deadline:
                    time.sleep(5.0)
                    continue
                raise
        if run_resp.get("failures"):
            raise AssertionError(f"RunTask could not place a Fargate task: {run_resp['failures']}")
        if not run_resp.get("tasks"):
            raise AssertionError("RunTask returned no tasks and no failures; cannot exercise ExecuteCommand")

        task_arn = run_resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(lambda: _safe_stop_task(ecs, cluster_arn, task_arn))

        def probe() -> str:
            # DescribeTasks can briefly return an empty list right after RunTask; treat it as PENDING.
            tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
            return tasks[0]["lastStatus"] if tasks else "PENDING"

        try:
            status = _poll_until(probe, lambda s: s in ("RUNNING", "STOPPED", "DEPROVISIONING"), timeout_s=180.0, interval_s=5.0)
        except AssertionError:
            raise AssertionError("task did not leave PENDING within the timeout; cannot exercise ExecuteCommand")
        if status != "RUNNING":
            raise AssertionError(
                f"task never reached RUNNING (last status {status!r}); cannot exercise ExecuteCommand"
            )
        return task_arn

    # Positive control: an exec-enabled task must not draw InvalidParameterException. It must
    # wait for the ExecuteCommandAgent to be RUNNING, since an earlier call also draws it.
    control_task_arn = _run_and_wait_running(enable_execute_command=True, task_role_arn=task_role_arn)

    def _exec_agent_status() -> str | None:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[control_task_arn])["tasks"]
        if not tasks:
            return None
        task = tasks[0]
        container = next((c for c in task.get("containers", []) if c["name"] == _CONTAINER_NAME), None)
        if container is None:
            return None
        agent = next((a for a in container.get("managedAgents", []) if a["name"] == "ExecuteCommandAgent"), None)
        return agent.get("lastStatus") if agent else None

    try:
        _poll_until(_exec_agent_status, lambda s: s == "RUNNING", timeout_s=240.0, interval_s=10.0)
    except AssertionError:
        raise AssertionError(
            "ExecuteCommandAgent never reached RUNNING on the enabled control task"
        )

    def _call_control():
        return _error(
            lambda: ecs.execute_command(
                cluster=cluster_arn, task=control_task_arn, container=_CONTAINER_NAME, command="echo hi", interactive=True
            )
        )

    # The managed agent reporting RUNNING can still race its own SSM registration by a few
    # seconds; retry that specific transient rather than accept one reading as proof the flag
    # failed to clear the launch-time gate.
    control = _poll_until(
        _call_control, lambda c: c[0] != "InvalidParameterException", timeout_s=60.0, interval_s=5.0
    )
    assert control == _SUCCEEDED, (
        "expected a task run WITH enableExecuteCommand, once its exec agent is connected, to "
        f"succeed, got {control!r}"
    )

    task_arn = _run_and_wait_running(enable_execute_command=False)
    error = _error(
        lambda: ecs.execute_command(
            cluster=cluster_arn, task=task_arn, container=_CONTAINER_NAME, command="echo hi", interactive=True
        )
    )
    assert error == _EXEC_NOT_AVAILABLE, (
        f"expected {_EXEC_NOT_AVAILABLE!r} calling ExecuteCommand on a task run without "
        f"enableExecuteCommand, got {error!r}"
    )

    # The rejected call must not have opened a session: the task's flag, status and agent
    # record stay exactly as they were.
    still = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert still["enableExecuteCommand"] is False, (
        f"enableExecuteCommand flipped True after a rejected ExecuteCommand call, got {still['enableExecuteCommand']!r}"
    )
    assert still["lastStatus"] != "STOPPED", (
        f"rejected ExecuteCommand call must not stop the task, got lastStatus={still['lastStatus']!r}"
    )
    stray_agents = [
        a for c in still.get("containers", []) for a in c.get("managedAgents", []) if a["name"] == "ExecuteCommandAgent"
    ]
    assert not stray_agents, f"unexpected ExecuteCommandAgent record on a task launched without the flag: {stray_agents}"




def _poll_until(probe, predicate, timeout_s: float = 20.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


# What _error returns for a call that succeeds; no AWS error code can equal it.
_SUCCEEDED = ("<succeeded>", None)


def _error(fn):
    """Call fn(); return its botocore (code, message), or _SUCCEEDED when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _SUCCEEDED


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)


def _create_ssm_task_role(ctx, iam) -> str:
    """A task role with the ssmmessages permissions ExecuteCommand's session channel needs.

    RunTask rejects enableExecuteCommand=True without a task role ("a valid task role is not
    being used")."""
    role_name = ctx.unique_name("sim2real-behav-ecsx-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    execution_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=execution_policy_arn)
    policy_name = "ecs-exec-ssmmessages"
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

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=execution_policy_arn)
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


def _default_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None
    return subnets[0]["SubnetId"]


def _safe_stop_task(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-behavioral-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _safe_deregister_task_def(ecs, td_arn: str) -> None:
    _retire_task_definition(ecs, td_arn)


def _safe_delete_cluster(ecs, cluster_arn: str) -> None:
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services or tasks remain, and a running task's ENI blocks
    deleting the network.
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
