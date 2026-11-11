"""execute-command-session-expiry."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "execute-command-session-expiry"
GROUP = 'execute-command'
SERVICES = ['ecs']


_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)


def _poll_until(fn, pred, *, timeout_s, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _register_fargate_td(ctx, ecs, **kwargs):
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        **kwargs,
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
    return arn


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each ExecuteCommand call on an exec-enabled task mints a fresh SSM session (distinct
    sessionId/tokenValue), and ExecuteCommand on a RUNNING task launched without
    enableExecuteCommand is rejected."""
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))

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
    role_name = ctx.unique_name("ecsExecTaskRole-")[:64]
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY))

    td_arn = _register_fargate_td(ctx, ecs, taskRoleArn=role_arn)

    def _attempt_run():
        try:
            run = ecs.run_task(
                cluster=name,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
                platformVersion="1.4.0",
                enableExecuteCommand=True,
            )
            if run.get("failures"):
                return RuntimeError(f"RunTask failures: {run['failures']}")
            candidate_arn = run["tasks"][0]["taskArn"]
            ctx.on_cleanup(
                lambda a=candidate_arn: ecs.stop_task(cluster=name, task=a, reason="behavioral-cleanup")
            )

            def _candidate_task():
                # DescribeTasks is eventually consistent right after RunTask —
                # the task ARN can be briefly absent, so tolerate an empty list
                # instead of indexing [0] and let the poll retry.
                tasks = ecs.describe_tasks(cluster=name, tasks=[candidate_arn])["tasks"]
                return tasks[0] if tasks else None

            state = _poll_until(
                _candidate_task,
                lambda t: t is not None and t["lastStatus"] in ("RUNNING", "STOPPED"),
                timeout_s=90,
            )
            if state["lastStatus"] == "RUNNING":
                return candidate_arn
            return RuntimeError(f"task stopped instead of RUNNING: {state.get('stoppedReason')!r}")
        except ClientError as exc:  # IAM propagation lag
            return exc

    result = _poll_until(_attempt_run, lambda r: isinstance(r, str), timeout_s=180, interval_s=15)
    assert isinstance(result, str), f"the exec-enabled task never reached RUNNING: {result!r}"
    task_arn = result

    def _exec_agent():
        t = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"][0]
        for c in t.get("containers", []):
            for ma in c.get("managedAgents", []):
                if ma.get("name") == "ExecuteCommandAgent":
                    return ma
        return None

    agent = _poll_until(
        _exec_agent,
        lambda ma: ma is not None and ma.get("lastStatus") == "RUNNING",
        timeout_s=240,
        interval_s=10,
    )
    assert agent["lastStatus"] == "RUNNING"

    session1 = ecs.execute_command(
        cluster=name, task=task_arn, container="app", command="/bin/sh", interactive=True
    )["session"]
    assert session1.get("sessionId") and session1.get("tokenValue") and session1.get("streamUrl"), (
        f"expected a full session (sessionId/tokenValue/streamUrl), got {session1}"
    )

    session2 = ecs.execute_command(
        cluster=name, task=task_arn, container="app", command="/bin/sh", interactive=True
    )["session"]
    assert session2["sessionId"] != session1["sessionId"], (
        "a second ExecuteCommand call must mint a genuinely NEW session, not reuse the first"
    )
    assert session2["tokenValue"] != session1["tokenValue"], (
        "a second ExecuteCommand call must mint a fresh tokenValue, not replay the first token"
    )

    active_sessions = ctx.client("ssm").describe_sessions(
        State="Active", Filters=[{"key": "SessionId", "value": session2["sessionId"]}]
    ).get("Sessions", [])
    assert active_sessions, (
        f"session {session2['sessionId']!r} returned by ExecuteCommand was never visible via "
        f"ssm:DescribeSessions(State=Active) -- the session was not backed by a real, "
        f"server-tracked SSM session"
    )
    assert active_sessions[0]["SessionId"] == session2["sessionId"]

    # overly-permissive boundary: no exec session for a non-exec-enabled task.
    plain_td_arn = _register_fargate_td(ctx, ecs)
    plain_run = ecs.run_task(
        cluster=name,
        taskDefinition=plain_td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
        enableExecuteCommand=False,
    )
    assert not plain_run.get("failures"), f"unexpected RunTask failures: {plain_run.get('failures')}"
    plain_task_arn = plain_run["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=plain_task_arn, reason="behavioral-cleanup"))
    def _plain_task():
        # DescribeTasks is eventually consistent right after RunTask — the task
        # ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0] and let the poll retry.
        tasks = ecs.describe_tasks(cluster=name, tasks=[plain_task_arn])["tasks"]
        return tasks[0] if tasks else None

    _poll_until(
        _plain_task,
        lambda t: t is not None and t["lastStatus"] == "RUNNING",
        timeout_s=180,
    )
    error = _error(
        lambda: ecs.execute_command(
            cluster=name, task=plain_task_arn, container="app", command="/bin/sh", interactive=True
        )
    )
    assert error == _EXEC_NOT_AVAILABLE, (
        f"expected {_EXEC_NOT_AVAILABLE!r} for a task without exec-command enabled, got {error!r}"
    )


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
