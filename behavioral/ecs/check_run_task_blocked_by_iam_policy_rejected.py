"""run-task-blocked-by-iam-policy-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-blocked-by-iam-policy-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]
_IAM_TAGS = [{"Key": "sim2real", "Value": "true"}]

_ALLOW_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
_ALLOW_ALL_DENY_RUN_TASK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "ecs:RunTask", "Resource": "*"},
    ],
}


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """(subnet ids, security group id) in a check-owned VPC with two public subnets behind an
    internet gateway, so a Fargate task can pull its public image; teardown waits out ENIs."""
    ec2 = ctx.client("ec2")
    made: dict = {"subnets": []}

    def _teardown_network():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 600
        for subnet_id in made["subnets"]:
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                    time.sleep(15)
        if made.get("igw"):
            ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=made["vpc"])
            ec2.delete_internet_gateway(InternetGatewayId=made["igw"])
        ec2.delete_vpc(VpcId=made["vpc"])

    made["vpc"] = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown_network)
    vpc_id = made["vpc"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ][:2]
    for i, zone in enumerate(zones):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.0.{i * 128}/25",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
        )["Subnet"]["SubnetId"]
        made["subnets"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    made["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=made["igw"])
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return list(made["subnets"]), sg_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _create_restricted_role(ctx, iam, sts):
    """Create a role trusted by this account with an unrestricted inline Allow policy; returns
    (role_name, role_arn). Callers swap the policy with ``put_role_policy``."""
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-ecs-denied-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    iam.put_role_policy(
        RoleName=role_name, PolicyName="restriction", PolicyDocument=json.dumps(_ALLOW_ALL_POLICY)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restriction"))
    return role_name, role_arn


def _assume_client(ctx, sts, service, role_arn, *, timeout_s=90):
    """Assume ``role_arn`` and return ``(client, session_name)`` for ``service``, retrying while
    a new role's trust policy propagates. Identity policy changes need no re-assumption."""
    session_name = ctx.unique_name("sess-")

    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            return exc

    creds = _poll_until(
        _try_assume,
        lambda r: not isinstance(r, Exception),
        timeout_s=timeout_s,
        interval_s=5,
        description="IAM role trust policy propagates enough for AssumeRole",
    )
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, session_name


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask succeeds under a broad Allow, is rejected with AccessDeniedException once
    ecs:RunTask is denied (no task per ListTasks), and succeeds again when the Deny is lifted."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    subnets, sg = _own_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    def _run_task():
        return restricted.run_task(
            cluster=cluster_name,
            taskDefinition=td["taskDefinitionArn"],
            launchType="FARGATE",
            networkConfiguration=net_cfg,
        )

    role_name, role_arn = _create_restricted_role(ctx, iam, sts)
    restricted, session_name = _assume_client(ctx, sts, "ecs", role_arn)
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: an unrestricted identity can run the task.
    resp = _run_task()
    assert not resp.get("failures"), f"positive-control RunTask reported failures: {resp['failures']}"
    control_task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_name, task=control_task_arn, reason="cleanup"))
    listed = ecs.list_tasks(cluster=cluster_name)["taskArns"]
    assert control_task_arn in listed, (
        f"expected the positive-control task {control_task_arn} to be visible via ListTasks, got {listed}"
    )
    ecs.stop_task(cluster=cluster_name, task=control_task_arn, reason="positive control teardown")

    # Deny ecs:RunTask only, leaving the broad Allow in place.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="restriction",
        PolicyDocument=json.dumps(_ALLOW_ALL_DENY_RUN_TASK_POLICY),
    )

    def _attempt_denied():
        try:
            resp = _run_task()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return ("refused", err.get("Code"), err.get("Message"))
        stray = (resp.get("tasks") or [None])[0]
        if stray:
            ecs.stop_task(cluster=cluster_name, task=stray["taskArn"], reason="policy propagation retry cleanup")
        # the inline-policy update has not propagated yet; the poll retries until it refuses
        return ("launched", None, None)

    # The specific error, then absence confirmed by an independent read.
    _, code, message = _poll_until(
        _attempt_denied,
        lambda r: r[0] == "refused",
        timeout_s=60,
        interval_s=5,
        description="ecs:RunTask denial to take effect after the inline policy update",
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a policy-blocked RunTask, got {code}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized to "
        f"perform: ecs:RunTask on resource: {td['taskDefinitionArn']} with an explicit deny in an "
        "identity-based policy"
    )
    assert message == expected_message, f"unexpected AccessDeniedException message: {message!r}"
    listed = ecs.list_tasks(cluster=cluster_name)["taskArns"]
    assert not listed, f"expected no task to have been launched by the blocked RunTask call, got {listed}"

    # Restore the Allow-only policy.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="restriction", PolicyDocument=json.dumps(_ALLOW_ALL_POLICY)
    )

    def _attempt_allowed():
        try:
            return _run_task()
        except ClientError as exc:
            return exc

    # The identical call now succeeds again.
    resp = _poll_until(
        _attempt_allowed,
        lambda r: not isinstance(r, ClientError),
        timeout_s=60,
        interval_s=5,
        description="ecs:RunTask to succeed again after the inline policy restore",
    )
    assert not resp.get("failures"), f"post-restore RunTask reported failures: {resp['failures']}"
    restored_task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_name, task=restored_task_arn, reason="cleanup"))
    listed = ecs.list_tasks(cluster=cluster_name)["taskArns"]
    assert restored_task_arn in listed, (
        f"expected the restored task {restored_task_arn} to be visible via ListTasks, got {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
