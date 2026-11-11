"""execute-command-session-credentials-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-session-credentials-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]

_ECS_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": "sim2real-ecs-exec-"},
]
_IAM_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecs-exec-"},
]
_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecs-exec-"},
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The session ExecuteCommand returns is a real SSM session: its sessionId is listed by
    DescribeSessions(State=Active), and the echoed clusterArn/taskArn/containerName match the
    task that was run."""
    ecs = ctx.client("ecs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    subnet_id, sg_id = _dedicated_fargate_network(ctx)

    exec_role_arn = _create_execution_role(ctx, iam)
    task_role_arn = _create_task_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-ecs-exec-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-exec-td-")
    taskdef_arn = ecs.register_task_definition(
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
                "name": "c",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "600"],
                "linuxParameters": {"initProcessEnabled": True},
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]

    def _cleanup_taskdef():
        ecs.deregister_task_definition(taskDefinition=taskdef_arn)
        ecs.delete_task_definitions(taskDefinitions=[taskdef_arn])

    ctx.on_cleanup(_cleanup_taskdef)

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    task_arn = _run_task_with_iam_retry(ecs, cluster_arn, taskdef_arn, net_cfg)

    def _cleanup_task():
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real check cleanup")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            desc = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
            if desc and desc[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_cleanup_task)

    _wait_for_exec_agent_ready(ecs, cluster_arn, task_arn, timeout_s=240)

    exec_resp = ecs.execute_command(
        cluster=cluster_arn,
        task=task_arn,
        container="c",
        interactive=True,
        command="echo sim2real-exec-check",
    )
    session = exec_resp["session"]
    assert session["sessionId"], "ExecuteCommand returned an empty sessionId"
    assert session["tokenValue"], "ExecuteCommand returned an empty tokenValue"
    assert session["streamUrl"], "ExecuteCommand returned an empty streamUrl"
    assert exec_resp["taskArn"] == task_arn
    assert exec_resp["clusterArn"] == cluster_arn
    assert exec_resp["containerName"] == "c"

    matched = _poll_for_ssm_session(ssm, session["sessionId"], timeout_s=30)
    assert matched is not None, (
        f"SessionId {session['sessionId']!r} returned by ExecuteCommand was never visible via "
        "ssm:DescribeSessions(State=Active) -- the session data was fabricated, not backed by a "
        "real SSM Session Manager session"
    )
    assert matched["SessionId"] == session["sessionId"]
    assert matched.get("Target"), "matching SSM session has no Target identifier"


# ===== helpers =====
def _dedicated_fargate_network(ctx):
    """A dedicated VPC/subnet/IGW for the exec-enabled Fargate task, never the account's
    default VPC, which a fresh account need not have."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 540
        # Fargate ENIs linger for a bit after the task stops; wait them out (the
        # task cleanup registered LATER runs FIRST under LIFO and has already
        # initiated the stop) so the subnet is deletable.
        while time.monotonic() < deadline:
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]).get(
                "NetworkInterfaces", []
            )
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
    return subnet_id, sg_id


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ecs-exec-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_IAM_TAGS
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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


def _create_task_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ecs-task-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_IAM_TAGS
    )["Role"]["Arn"]
    ssmmessages_policy = json.dumps(
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
    )
    policy_name = "ecs-exec-ssmmessages"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=ssmmessages_policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
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


def _run_task_with_iam_retry(ecs, cluster_arn, taskdef_arn, net_cfg, attempts: int = 8, delay_s: float = 8.0):
    last_error = None
    for _ in range(attempts):
        try:
            resp = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=taskdef_arn,
                launchType="FARGATE",
                count=1,
                enableExecuteCommand=True,
                networkConfiguration=net_cfg,
                tags=_ECS_TAGS,
            )
        except ClientError as exc:
            last_error = exc
            time.sleep(delay_s)
            continue
        if resp.get("tasks"):
            return resp["tasks"][0]["taskArn"]
        last_error = AssertionError(f"RunTask placed no task: failures={resp.get('failures')}")
        time.sleep(delay_s)
    raise AssertionError(f"RunTask never succeeded after IAM-propagation retries: {last_error}")


def _wait_for_exec_agent_ready(ecs, cluster_arn, task_arn, timeout_s: float = 240.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_task = None
    while time.monotonic() < deadline:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        if not tasks:
            time.sleep(interval_s)
            continue
        last_task = tasks[0]
        if last_task["lastStatus"] == "STOPPED":
            raise AssertionError(f"task stopped before becoming ready for exec: {last_task.get('stoppedReason')}")
        if last_task["lastStatus"] == "RUNNING":
            for container in last_task.get("containers", []):
                for agent in container.get("managedAgents", []):
                    if agent.get("name") == "ExecuteCommandAgent" and agent.get("lastStatus") == "RUNNING":
                        return
        time.sleep(interval_s)
    raise AssertionError(f"ExecuteCommandAgent never reached RUNNING within {timeout_s}s: last_task={last_task}")


def _poll_for_ssm_session(ssm, session_id: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sessions = ssm.describe_sessions(State="Active").get("Sessions", [])
        for s in sessions:
            if s.get("SessionId") == session_id:
                return s
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
