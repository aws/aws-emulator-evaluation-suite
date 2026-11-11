"""managed-action-history-retains-completed-actions-ttl."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-action-history-retains-completed-actions-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After ApplyEnvironmentManagedAction completes, the action leaves the live list and
    appears with a terminal Completed status in DescribeEnvironmentManagedActionHistory."""
    app_name = _create_app(ctx)
    start_time = _preferred_start_time(minutes_ahead=8)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": start_time},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
        # InstanceRefreshEnabled schedules a weekly "replace all instances" managed action whether
        # or not a newer platform version exists, so a real managed action is available on demand.
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
    ]
    env_name = _create_ready_environment(ctx, app_name, extra_option_settings=option_settings)

    action = _wait_for_managed_action(ctx, env_name, timeout_s=1200.0)
    action_id = action["ActionId"]

    eb = ctx.client("elasticbeanstalk")
    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)

    def _live_match() -> dict | None:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        return next((a for a in actions if a["ActionId"] == action_id), None)

    # An instance refresh replaces the environment's instance, so the applied action can stay
    # live (Pending, then Running) for well over twenty minutes before it settles.
    deadline = time.monotonic() + 2100.0
    live = _live_match()
    while live is not None:
        if time.monotonic() >= deadline:
            env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
            events = eb.describe_events(EnvironmentName=env_name, MaxRecords=5).get("Events", [])
            raise AssertionError(
                f"applied managed action {action_id} was still live after 2100s: "
                f"action={live!r} env={env['Status']}/{env.get('Health')} "
                f"events={[e['Message'] for e in events]!r}")
        time.sleep(2.0)
        live = _live_match()

    def _history_status() -> str | None:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        match = next((i for i in items if i["ActionId"] == action_id), None)
        return match["Status"] if match else None

    status = None
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        status = _history_status()
        if status is not None:
            break
        time.sleep(2)
    # ActionHistoryStatus is a closed enum {Completed, Failed, Unknown} -- "Success" is not a
    # member of it and can never be returned; a completed managed action is reported "Completed".
    assert status == "Completed", f"expected completed action in history with Status=Completed, got {status!r}"


_EB_PREFIX = "sim2real-eb-"


def _eb_name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_EB_PREFIX}{kind}-")


def _preferred_start_time(minutes_ahead: int = 3) -> str:
    now = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes_ahead)
    return f"{now.strftime('%a')}:{now.strftime('%H:%M')}"


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    python_stacks = [s for s in stacks if "Python" in s and "Amazon Linux 2" in s and "Docker" not in s]
    candidates = python_stacks or [s for s in stacks if "Python" in s] or stacks
    return candidates[-1]


_TAGS = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]


def _create_app(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    app_name = _eb_name(ctx, "app")
    eb.create_application(ApplicationName=app_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    return app_name


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "ec2role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=_TAGS)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)

    def _cleanup() -> None:
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_instance_profile(InstanceProfileName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
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
    return role_name


def _create_eb_service_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "svcrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_env_with_retry(eb: Any, kwargs: dict, attempts: int = 8, delay_s: float = 10.0) -> None:
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            eb.create_environment(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "InsufficientPrivilegesException":
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _wait_for_env_status(
    ctx: Any, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 2.0
) -> str:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _terminate_environment(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Teardown: terminate the environment and wait until it is Terminated, so the VPC delete
    registered before it can follow. An environment that is already gone counts as terminated;
    one still launching or updating is retried until the deadline; any other error raises."""
    from botocore.exceptions import ClientError

    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name]).get("Environments", [])
        status = envs[0]["Status"] if envs else "Terminated"
        if status in ("Terminating", "Terminated"):
            break
        try:
            eb.terminate_environment(EnvironmentName=env_name)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValue" or time.monotonic() >= deadline:
                raise
            if err.get("Message", "").startswith("No Environment found"):
                return
        time.sleep(interval_s)
    _wait_for_env_status(ctx, env_name, {"Terminated"}, timeout_s=max(deadline - time.monotonic(), interval_s),
                         interval_s=interval_s)


def _create_public_vpc(ctx):
    """Create a VPC with one public subnet for the environment, so the launch never depends on
    the account's default VPC. Cleanup is registered first, so it runs after the environment's."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eb-vpc-")
    tags = [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tags}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.42.0.0/24", AvailabilityZone=sorted(z["ZoneName"] for z in zones)[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": tags}]
    )["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
    return vpc_id, subnet_id


def _vpc_options(vpc_id, subnet_id):
    return [
        {"Namespace": "aws:ec2:vpc", "OptionName": "VPCId", "Value": vpc_id},
        {"Namespace": "aws:ec2:vpc", "OptionName": "Subnets", "Value": subnet_id},
        {"Namespace": "aws:ec2:vpc", "OptionName": "AssociatePublicIpAddress", "Value": "true"},
    ]


def _delete_vpc(ec2, vpc_id, timeout_s=240.0, interval_s=2.0):
    """Tear the VPC down, retrying while the environment's network interfaces drain."""
    from botocore.exceptions import ClientError

    flt = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for sn in ec2.describe_subnets(Filters=flt)["Subnets"]:
                ec2.delete_subnet(SubnetId=sn["SubnetId"])
            for rt in ec2.describe_route_tables(Filters=flt)["RouteTables"]:
                if not any(a.get("Main") for a in rt.get("Associations", [])):
                    ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
            igws = ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )["InternetGateways"]
            for igw in igws:
                ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
                ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
            for sg in ec2.describe_security_groups(Filters=flt)["SecurityGroups"]:
                if sg["GroupName"] != "default":
                    ec2.delete_security_group(GroupId=sg["GroupId"])
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_ready_environment(ctx: Any, app_name: str, extra_option_settings: list | None = None) -> str:
    eb = ctx.client("elasticbeanstalk")
    env_name = _eb_name(ctx, "env")
    stack = _pick_solution_stack(ctx)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    # The check's own VPC, created before the environment so its teardown runs after the
    # environment's: the launch never depends on the account's default VPC.
    vpc_id, subnet_id = _create_public_vpc(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        *_vpc_options(vpc_id, subnet_id),
    ]
    if extra_option_settings:
        option_settings.extend(extra_option_settings)
    kwargs = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "SolutionStackName": stack,
        "OptionSettings": option_settings,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    _create_env_with_retry(eb, kwargs)
    ctx.on_cleanup(lambda: _terminate_environment(ctx, env_name))
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, interval_s=2.0)
    return env_name


def _wait_for_managed_action(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> dict:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        )
        if actions:
            return actions[0]
        time.sleep(interval_s)
    raise AssertionError(
        "AWS never scheduled a managed action for this environment within the poll window - the "
        "chosen platform may already be at its latest version, or the recommendation engine had not "
        "run yet; would be closed by re-running once a platform update is actually pending"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
