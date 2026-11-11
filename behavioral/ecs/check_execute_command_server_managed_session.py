"""execute-command-server-managed-session."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-server-managed-session"
GROUP = 'task-execution'
SERVICES = ['ecs']

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _fargate_network(ctx):
    """Return (subnets, sg) for launching Fargate (awsvpc) tasks.

    A dedicated VPC with a public subnet, internet gateway and default route, so
    the task can pull its public-ECR image; a fresh account need not have a
    default VPC. The whole stack is torn down by ONE registered cleanup that
    first waits out the Fargate ENI-detachment lag (ENIs linger briefly after a
    task/service stops and block subnet deletion)."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 540
        # Fargate ENIs linger for a bit after tasks stop; wait them out (the
        # service/task cleanups registered LATER run FIRST under LIFO and have
        # already initiated the stop) so the subnet is deletable.
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", [])
            if not enis:
                break
            time.sleep(2)
        while True:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidSubnetID.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "Gateway.NotAttached",
                "InvalidInternetGatewayID.NotFound",
            ):
                raise
        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
                raise
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidVpcID.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_teardown_network)
    return [subnet_id], sg_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _refusal(fn):
    """The Error of the ClientError ``fn`` raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call unexpectedly succeeded")


def _create_ecs_exec_task_role(ctx):
    """A minimal ecs-tasks.amazonaws.com-trusted task role with the four
    ssmmessages permissions ECS Exec's brokered session needs.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("ecsExecTaskRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return resp["Role"]["Arn"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a RUNNING exec-enabled Fargate task, ExecuteCommand returns a non-empty SSM session
    (sessionId/streamUrl/tokenValue) tied to that task and container; on a task launched without
    enableExecuteCommand it is rejected rather than brokering a session."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }
    task_role_arn = _create_ecs_exec_task_role(ctx)
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    task_def = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        taskRoleArn=task_role_arn,
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def["taskDefinitionArn"]))

    def _run_with_role_retry(**kwargs):
        # The task role's trust policy was just created; ECS's own PassRole/
        # AssumeRole check against it can lag briefly. Retry RunTask itself.
        def _try():
            try:
                resp = ecs.run_task(
                    cluster=name,
                    taskDefinition=task_def["taskDefinitionArn"],
                    launchType="FARGATE",
                    count=1,
                    networkConfiguration=net_cfg,
                    **kwargs,
                )
                return resp
            except Exception as exc:  # noqa: BLE001
                return exc

        result = _poll_until(
            _try,
            lambda r: not isinstance(r, Exception),
            timeout_s=90,
            interval_s=10,
            description="the freshly created task role propagates enough for ECS to assume it",
        )
        if isinstance(result, Exception):
            raise result
        for t in result.get("tasks", []):
            ctx.on_cleanup(
                lambda a=t["taskArn"]: ecs.stop_task(cluster=name, task=a, reason="behavioral-cleanup")
            )
        return result

    # overly-permissive boundary first (cheaper): a task launched without
    # enableExecuteCommand must reject ExecuteCommand outright.
    plain_run = _run_with_role_retry()
    assert not plain_run.get("failures"), plain_run.get("failures")
    plain_task_arn = plain_run["tasks"][0]["taskArn"]
    def _plain_task():
        # DescribeTasks is eventually consistent right after RunTask — the task
        # ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0] and let the poll retry.
        tasks = ecs.describe_tasks(cluster=name, tasks=[plain_task_arn])["tasks"]
        return tasks[0] if tasks else None

    _poll_until(
        _plain_task,
        lambda t: t is not None and t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=180,
        interval_s=5,
        description="the non-exec-enabled task reaches RUNNING",
    )
    error = _refusal(
        lambda: ecs.execute_command(
            cluster=name, task=plain_task_arn, container="app", command="echo hi", interactive=True
        )
    )
    code = error.get("Code")
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException executing a command against a task without "
        f"enableExecuteCommand, got {code}"
    )
    message = error.get("Message")
    assert message == (
        "The execute command failed because execute command was not enabled when the task was run or the "
        "execute command agent isn't running. Wait and try again or run a new task with execute command "
        "enabled and try again."
    ), f"expected the execute-command-not-enabled message, got {message!r}"

    exec_run = _run_with_role_retry(enableExecuteCommand=True)
    assert not exec_run.get("failures"), exec_run.get("failures")
    exec_task_arn = exec_run["tasks"][0]["taskArn"]

    def _managed_agent():
        # DescribeTasks is eventually consistent right after RunTask — the task
        # ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0] and let the poll retry.
        tasks = ecs.describe_tasks(cluster=name, tasks=[exec_task_arn])["tasks"]
        if not tasks:
            return None
        t = tasks[0]
        for c in t.get("containers", []):
            for a in c.get("managedAgents", []):
                if a.get("name") == "ExecuteCommandAgent":
                    return a
        return None

    _poll_until(
        _managed_agent,
        lambda a: a is not None and a.get("lastStatus") == "RUNNING",
        timeout_s=240,
        interval_s=10,
        description="the platform-managed ExecuteCommandAgent becomes RUNNING on the Fargate task",
    )

    resp = ecs.execute_command(
        cluster=name, task=exec_task_arn, container="app", command="echo hello-from-exec", interactive=True
    )
    assert resp.get("taskArn") == exec_task_arn, resp
    assert resp.get("containerName") == "app", resp
    session = resp.get("session", {})
    assert session.get("sessionId"), f"expected a non-empty brokered SSM sessionId, got {resp}"
    assert session.get("streamUrl"), f"expected a non-empty brokered SSM streamUrl, got {resp}"
    assert session.get("tokenValue"), f"expected a non-empty brokered SSM tokenValue, got {resp}"

    # The session ECS just handed back could be a fabricated blob; confirm it is backed by
    # a REAL SSM Session Manager session by looking it up through SSM itself (a different
    # service, different operation, at the actual destination) rather than trusting ECS's
    # own echo of what it just returned.
    ssm = ctx.client("ssm")
    session_id = session["sessionId"]

    def _matching_ssm_session():
        sessions = ssm.describe_sessions(
            State="Active", Filters=[{"key": "SessionId", "value": session_id}]
        ).get("Sessions", [])
        return next((s for s in sessions if s.get("SessionId") == session_id), None)

    matched = _poll_until(
        _matching_ssm_session,
        lambda s: s is not None,
        timeout_s=30,
        interval_s=3,
        description=(
            f"sessionId {session_id!r} returned by ExecuteCommand becomes visible via "
            "ssm:DescribeSessions(State=Active)"
        ),
    )
    assert matched["SessionId"] == session_id, matched
    assert matched.get("Target"), f"matching SSM session has no Target identifier, got {matched}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
