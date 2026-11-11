"""execute-command-requires-enabled-flag-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-command-requires-enabled-flag-rejected"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand on a RUNNING Fargate task launched without enableExecuteCommand is rejected up
    front with InvalidParameterException; the same container launched WITH the flag and an
    ssmmessages task role clears that gate (success or TargetNotConnectedException only)."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place a Fargate task")
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
    sg_id = sgs[0]["GroupId"]
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    cluster_name = ctx.unique_name("sim2real-behav-ecs-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    family = ctx.unique_name("sim2real-behav-ecs-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        enableExecuteCommand=False,
        networkConfiguration=net_cfg,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    if not run_resp.get("tasks"):
        reason = (run_resp.get("failures") or [{}])[0].get("reason", "unknown")
        raise AssertionError(f"could not launch a Fargate task in this account/VPC: {reason}")

    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_and_wait(cl_arn, t_arn):
        try:
            ecs.stop_task(cluster=cl_arn, task=t_arn, reason="sim2real-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        try:
            _poll_until(
                lambda: ecs.describe_tasks(cluster=cl_arn, tasks=[t_arn])["tasks"][0]["lastStatus"],
                lambda s: s == "STOPPED",
                timeout_s=90,
                interval_s=5,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(lambda: _stop_and_wait(cluster_arn, task_arn))

    last_status = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda s: s in ("RUNNING", "STOPPED"),
        timeout_s=180,
        interval_s=5,
    )
    if last_status != "RUNNING":
        task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
        raise AssertionError(
            f"Fargate task never reached RUNNING (status={last_status}, "
            f"stoppedReason={task.get('stoppedReason')})"
        )

    error = _error(
        lambda: ecs.execute_command(cluster=cluster_arn, task=task_arn, command="echo hi", interactive=True)
    )
    assert error == _EXEC_NOT_AVAILABLE, (
        "real ECS rejects execute-command for a task launched without enableExecuteCommand up "
        f"front, before ever attempting an SSM connection: expected {_EXEC_NOT_AVAILABLE!r}, got {error!r}"
    )

    # Independent read: the rejected call left no trace -- no ExecuteCommandAgent was ever
    # injected (it only exists when the flag is set), the task kept running, and the flag itself
    # did not flip. This is what makes the rejection "up front" rather than merely transient.
    not_enabled_task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert not_enabled_task["enableExecuteCommand"] is False, (
        f"a rejected ExecuteCommand must not flip the task's own enableExecuteCommand flag, "
        f"got {not_enabled_task['enableExecuteCommand']!r}"
    )
    assert not_enabled_task["desiredStatus"] != "STOPPED", (
        f"a rejected ExecuteCommand must not stop the task, got desiredStatus="
        f"{not_enabled_task['desiredStatus']!r}"
    )
    exec_agent = next(
        (
            agent
            for container in not_enabled_task.get("containers", [])
            for agent in container.get("managedAgents", [])
            if agent.get("name") == "ExecuteCommandAgent"
        ),
        None,
    )
    assert exec_agent is None, (
        f"a task launched without enableExecuteCommand must never have an ExecuteCommandAgent "
        f"managed agent at all, got {exec_agent!r}"
    )

    # Positive control: same cluster/image WITH the flag and an ssmmessages task role, so a target
    # that rejects execute-command outright cannot pass by coincidence.
    task_role_arn = _create_ssm_task_role(ctx, iam)

    family_pc = ctx.unique_name("sim2real-behav-ecs-td-pc-")
    task_def_pc_arn = ecs.register_task_definition(
        family=family_pc,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_pc_arn))

    run_resp_pc = None
    last_failure = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            run_resp_pc = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=task_def_pc_arn,
                launchType="FARGATE",
                count=1,
                enableExecuteCommand=True,
                networkConfiguration=net_cfg,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
        except Exception as exc:  # noqa: BLE001 -- a freshly-created IAM role is eventually consistent
            last_failure = str(exc)
            if "assume" in str(exc).lower():
                time.sleep(5)
                continue
            raise
        if run_resp_pc.get("tasks"):
            break
        last_failure = run_resp_pc.get("failures")
        time.sleep(5)
    if not run_resp_pc or not run_resp_pc.get("tasks"):
        raise AssertionError(f"positive-control RunTask never placed a task: {last_failure}")

    task_pc_arn = run_resp_pc["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_wait(cluster_arn, task_pc_arn))

    last_status_pc = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_pc_arn])["tasks"][0]["lastStatus"],
        lambda s: s in ("RUNNING", "STOPPED"),
        timeout_s=180,
        interval_s=5,
    )
    if last_status_pc != "RUNNING":
        task_pc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_pc_arn])["tasks"][0]
        raise AssertionError(
            f"positive-control Fargate task never reached RUNNING (status={last_status_pc}, "
            f"stoppedReason={task_pc.get('stoppedReason')})"
        )

    described_pc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_pc_arn])["tasks"][0]
    assert described_pc["enableExecuteCommand"] is True, (
        "positive-control task launched with enableExecuteCommand=True must report it as such"
    )

    # The exec agent registers with SSM some time after the task is RUNNING; until then the call
    # gets the SAME InvalidParameterException as the disabled case, so wait (bounded) for it.
    agent_deadline = time.monotonic() + 180
    agent_status = None
    while time.monotonic() < agent_deadline:
        described_pc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_pc_arn])["tasks"][0]
        agent_status = None
        for container in described_pc.get("containers", []):
            for agent in container.get("managedAgents", []):
                if agent.get("name") == "ExecuteCommandAgent":
                    agent_status = agent.get("lastStatus")
        if agent_status == "RUNNING":
            break
        time.sleep(5)

    # Even with the agent RUNNING, the first call can race its SSM registration and briefly get
    # InvalidParameterException, so retry (bounded).
    retry_deadline = time.monotonic() + 60
    while True:
        error_pc = _error(
            lambda: ecs.execute_command(
                cluster=cluster_arn, task=task_pc_arn, command="echo hi", interactive=True
            )
        )
        if error_pc[0] != "InvalidParameterException":
            break
        if time.monotonic() >= retry_deadline:
            break
        time.sleep(5)

    assert error_pc[0] not in ("InvalidParameterException", "ClientException"), (
        "enabling the flag must clear the launch-time gate; got the SAME disabled-flag "
        f"rejection ({error_pc!r}) even after the managed agent reported status={agent_status!r} "
        "-- this check cannot tell 'rejects a disabled task' from 'rejects execute-command "
        "outright' without a working positive control"
    )
    assert error_pc == _SUCCEEDED or error_pc[0] == "TargetNotConnectedException", (
        f"expected either success or TargetNotConnectedException once the flag is enabled, got {error_pc!r}"
    )



def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ClusterNotFoundException", "NoSuchEntity"):
            raise


def _create_ssm_task_role(ctx, iam) -> str:
    """A task role for ecs-tasks.amazonaws.com with only the ssmmessages permissions the exec agent
    needs; without a task role RunTask rejects enableExecuteCommand=True outright."""
    role_name = ctx.unique_name("sim2real-behav-ecs-exec-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-ecs-exec-ssmmessages"
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
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    # IAM role propagation lag before ECS/STS will accept it as a task role.
    _poll_until(
        lambda: _error(lambda: iam.get_role(RoleName=role_name)),
        lambda error: error == _SUCCEEDED,
        timeout_s=15.0,
        interval_s=2.0,
    )
    return role_arn


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


# What _error returns for a call that succeeds; no AWS error code can equal it.
_SUCCEEDED = ("<succeeded>", None)


def _error(fn):
    """Call fn(); return its botocore (code, message), or _SUCCEEDED when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


# ExecuteCommand's refusal while the task's exec agent is not running, or exec is not enabled.
_EXEC_NOT_AVAILABLE = (
    "InvalidParameterException",
    "The execute command failed because execute command was not enabled when the task was run "
    "or the execute command agent isn't running. Wait and try again or run a new task with "
    "execute command enabled and try again.",
)


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
