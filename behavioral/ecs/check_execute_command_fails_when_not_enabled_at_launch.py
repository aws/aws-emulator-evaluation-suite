"""execute-command-fails-when-not-enabled-at-launch."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-command-fails-when-not-enabled-at-launch"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-execnoenable"},
]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand on a task launched without enableExecuteCommand is refused
    InvalidParameterException with the exact message and the task keeps running, while the same
    task definition launched with it passes that gate (no error or TargetNotConnectedException)."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_networking(ctx)

    # RunTask with enableExecuteCommand=True is itself refused by real ECS
    # (InvalidParameterException: "a valid task role is not configured") unless the task definition
    # carries a taskRoleArn -- the managed exec agent assumes that role to talk to SSM. This check
    # isn't exercising SSM connectivity itself, so any task role satisfies the launch-time gate; we
    # still grant the exec role and minimal ssmmessages permissions so the positive control can
    # genuinely reach RunTask acceptance and get as far as its own SSM-connectivity precondition.
    exec_role_arn = _create_role(
        ctx,
        "sim2real-execnoenable-exrole-",
        "ecs-tasks.amazonaws.com",
        policy_arns=["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
    )
    task_role_arn = _create_role(
        ctx,
        "sim2real-execnoenable-taskrole-",
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

    cluster_name = ctx.unique_name("sim2real-execnoenable-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real:managed", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-execnoenable-td")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    # assignPublicIp must be ENABLED: the shared network's public subnets have no
    # NAT gateway, so a task with no public IP can never reach the public image
    # registry or the SSM endpoints its managed exec agent needs -- it would
    # never leave PENDING/PROVISIONING, which would make the positive-control
    # task below indistinguishable from the launch-time-gate rejection this
    # check is isolating.
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    # --- Negative case: launched WITHOUT enableExecuteCommand ---
    task1_arn = None
    run1 = None
    last_error = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            run1 = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except Exception as exc:  # noqa: BLE001
            # Freshly-created IAM roles are eventually consistent -- ECS can
            # transiently fail to assume the just-created execution/task role for a
            # short window after CreateRole/AttachRolePolicy. Retry rather than
            # treat this as a real rejection.
            last_error = exc
            if "assume" in str(exc).lower():
                time.sleep(5)
                continue
            raise
        if run1["tasks"]:
            break
        last_error = run1["failures"]
        time.sleep(5)
    assert run1 is not None and run1["tasks"], f"RunTask never placed a task: {last_error}"
    assert run1["failures"] == [], f"unexpected RunTask failures: {run1['failures']}"
    task1 = run1["tasks"][0]
    task1_arn = task1["taskArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.stop_task(cluster=cluster_arn, task=task1_arn)))
    assert task1["enableExecuteCommand"] is False, "task launched without the flag must report enableExecuteCommand=False"

    code1, msg1 = _try_execute_command(ecs, cluster_arn, task1_arn)
    assert code1 == "InvalidParameterException", (
        f"expected InvalidParameterException for exec on a not-enabled task, got {code1}: {msg1}"
    )
    assert msg1 == "The execute command failed because execute command was not enabled when the task was run or the execute command agent isn't running. Wait and try again or run a new task with execute command enabled and try again.", f"unexpected message: {msg1!r}"

    # confirm the forbidden effect really did not happen: task record is unchanged / no session
    still = ecs.describe_tasks(cluster=cluster_arn, tasks=[task1_arn])["tasks"][0]
    assert still["enableExecuteCommand"] is False, "task's enableExecuteCommand flipped after a rejected ExecuteCommand"
    assert still["desiredStatus"] != "STOPPED", (
        f"rejected ExecuteCommand call must not stop the task, got desiredStatus={still['desiredStatus']!r}"
    )

    # --- Positive control: same task def, launched WITH enableExecuteCommand ---
    run2 = None
    last_error2 = None
    deadline2 = time.monotonic() + 60
    while time.monotonic() < deadline2:
        try:
            run2 = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                enableExecuteCommand=True,
                networkConfiguration=net_cfg,
            )
        except Exception as exc:  # noqa: BLE001
            last_error2 = exc
            if "assume" in str(exc).lower():
                time.sleep(5)
                continue
            raise
        if run2["tasks"]:
            break
        last_error2 = run2["failures"]
        time.sleep(5)
    assert run2 is not None and run2["tasks"], f"RunTask never placed a task: {last_error2}"
    assert run2["failures"] == [], f"unexpected RunTask failures: {run2['failures']}"
    task2 = run2["tasks"][0]
    task2_arn = task2["taskArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.stop_task(cluster=cluster_arn, task=task2_arn)))
    assert task2["enableExecuteCommand"] is True, "task launched with the flag must report enableExecuteCommand=True"

    # ExecuteCommand requires the task to have actually reached RUNNING --
    # calling it while the task is still PENDING/PROVISIONING yields the same
    # generic InvalidParameterException as the launch-time-gate rejection
    # this check is isolating, for the wrong reason (task not started yet,
    # rather than the flag being unset). Poll (bounded) until the task is
    # RUNNING so the result we observe is attributable to the flag alone.
    task2_running = None
    deadline3 = time.monotonic() + 180
    while time.monotonic() < deadline3:
        task2_running = ecs.describe_tasks(cluster=cluster_arn, tasks=[task2_arn])["tasks"][0]
        if task2_running["lastStatus"] in ("RUNNING", "STOPPED"):
            break
        time.sleep(5)
    assert task2_running is not None and task2_running["lastStatus"] == "RUNNING", (
        "positive-control task never reached RUNNING within the poll budget: "
        f"{task2_running['lastStatus'] if task2_running else None}"
    )

    # Reaching lastStatus == RUNNING on the task does not mean the managed
    # ExecuteCommandAgent sidecar has finished starting and registered with SSM
    # yet -- for a short window after the task goes RUNNING, real ECS still
    # answers ExecuteCommand with the SAME InvalidParameterException as the
    # disabled-flag case (it just hasn't set up the exec channel yet), which
    # has nothing to do with the launch-time gate this check is isolating.
    # Poll (bounded) for the ExecuteCommandAgent managed-agent status to reach
    # RUNNING before treating an InvalidParameterException as meaningful.
    deadline4 = time.monotonic() + 180
    agent_status = None
    while time.monotonic() < deadline4:
        described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task2_arn])["tasks"][0]
        containers = described.get("containers", [])
        agent_status = None
        for container in containers:
            for agent in container.get("managedAgents", []):
                if agent.get("name") == "ExecuteCommandAgent":
                    agent_status = agent.get("lastStatus")
        if agent_status == "RUNNING":
            break
        time.sleep(5)

    # Even once the managed agent reports RUNNING, the very first
    # ExecuteCommand call can still race the agent's SSM registration and come
    # back with the same InvalidParameterException momentarily -- retry
    # (bounded) rather than treat a single transient InvalidParameterException
    # as proof the flag failed to clear the gate.
    code2, msg2 = None, None
    deadline5 = time.monotonic() + 60
    while time.monotonic() < deadline5:
        code2, msg2 = _try_execute_command(ecs, cluster_arn, task2_arn)
        if code2 != "InvalidParameterException":
            break
        time.sleep(5)

    assert code2 != "InvalidParameterException", (
        "enabling the flag must clear the launch-time gate; got the SAME rejection as the disabled case "
        f"even after the managed agent reported status={agent_status}: {msg2}"
    )
    assert code2 in (None, "TargetNotConnectedException"), (
        f"expected either success or TargetNotConnectedException once the flag is enabled, got {code2}: {msg2}"
    )
    # message varies: TargetNotConnectedException is the race outcome of an agent that has
    # not yet connected; live runs take the success path, so no message is observed to pin.


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


#: The ecs suite's cleanup budget; DeleteCluster is retried within it while tasks or services drain.
_CLEANUP_S = 900.0
_DRAINING = ("ClusterContainsTasksException", "ClusterContainsServicesException")


def _delete_cluster(ecs, arn: str) -> None:
    """Delete the cluster, retrying every 2 s while stopped tasks or deleted services still drain;
    an already-gone cluster is done, anything else (or a drain past the budget) raises."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            ecs.delete_cluster(cluster=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in _DRAINING or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _try_execute_command(ecs, cluster_arn: str, task_arn: str):
    """Returns (error_code_or_None, message)."""
    from botocore.exceptions import ClientError

    try:
        resp = ecs.execute_command(
            cluster=cluster_arn, task=task_arn, command="echo hi", interactive=True
        )
        return None, resp.get("session", {}).get("sessionId", "")
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")


def _create_role(ctx, prefix, trust_service, policy_arns=(), inline_policies=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_NET_TAGS
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


def _default_networking(ctx):
    """(subnet, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return net.subnet_ids[0], net.security_group_id


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
