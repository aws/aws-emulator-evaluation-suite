"""apply-environment-managed-action-executes-server-side-update."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apply-environment-managed-action-executes-server-side-update"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Applying a scheduled managed action performs a real update: the action ends Completed in
    the managed-action history, the environment settles back to Ready, and its instances are
    all replaced."""
    eb = ctx.client("elasticbeanstalk")
    app_name = _create_app(ctx)
    start_time = _preferred_start_time(minutes_ahead=3)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": start_time},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
        # A PlatformUpdate action needs a newer platform version on the branch, which may not
        # exist; instance refresh schedules a "replace all instances" action regardless.
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
    ]
    env_name = _create_ready_environment(ctx, app_name, extra_option_settings=option_settings)

    action = _wait_for_managed_action(ctx, env_name, timeout_s=_budget_s(ctx, 1200.0))
    instances_before = _instance_ids(eb, env_name)
    assert instances_before, f"environment {env_name} reported no instances before the managed action"

    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action["ActionId"])

    item = _wait_for_history_terminal(ctx, env_name, action["ActionId"], timeout_s=_budget_s(ctx, 1800.0))
    assert item["Status"] == "Completed", (
        f"the applied managed action must finish Completed in the managed-action history, got {item!r}"
    )

    final_status = _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=_budget_s(ctx, 1200.0), interval_s=1.0)
    assert final_status == "Ready", f"expected environment to settle back to Ready after the managed update, got {final_status!r}"

    instances_after = _instance_ids(eb, env_name)
    assert instances_after and instances_after.isdisjoint(instances_before), (
        f"the applied InstanceRefresh action did not replace the environment's instances "
        f"(before={sorted(instances_before)}, after={sorted(instances_after)}) - no real server-side update occurred"
    )


_EB_PREFIX = "sim2real-eb-"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _create_app(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    app_name = _eb_name(ctx, "app")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    return app_name


def _create_eb_instance_profile(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = _eb_name(ctx, "ec2role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags)
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=tags)
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
    tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tags)["Role"]
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


def _create_env_with_retry(eb: Any, kwargs: dict, attempts: int = 40, delay_s: float = 2.0) -> None:
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
    if _budget_spent(ctx):
        raise TimeoutError(f"environment {env_name} reaching {target_statuses}: the run budget "
                           f"ended first; not graded")
    raise AssertionError(f"environment {env_name} did not reach {target_statuses} within {timeout_s}s (last={last_status})")


def _instance_ids(eb: Any, env_name: str) -> set[str]:
    resources = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
    return {i["Id"] for i in resources.get("Instances", [])}


def _wait_for_history_terminal(
    ctx: Any, env_name: str, action_id: str, timeout_s: float = 1800.0, interval_s: float = 1.0
) -> dict:
    """Poll the managed-action history until ``action_id`` has a terminal entry; raise on timeout."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while True:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item.get("ActionId") == action_id and item.get("Status") in ("Completed", "Failed"):
                return item
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"managed action {action_id} reaching a terminal history entry: "
                                   f"the run budget ended first; not graded")
            raise AssertionError(
                f"managed action {action_id} never reached a terminal history entry within {timeout_s}s "
                f"(history={items!r})"
            )
        time.sleep(interval_s)


def _terminate_environment(ctx: Any, env_name: str) -> None:
    eb = ctx.client("elasticbeanstalk")
    # A managed update the check applied may still be running; EB refuses to terminate an
    # environment mid-update, so let it settle first.
    _wait_for_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=840.0, interval_s=15.0)
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as last:
        # EB answers InvalidParameterValue for an environment that no longer exists: done only
        # when DescribeEnvironments confirms it is gone or Terminated.
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if envs and envs[0]["Status"] != "Terminated":
            raise RuntimeError(f"environment {env_name} was not deleted: {last!r}") from last
        return
    _wait_for_env_status(ctx, env_name, {"Terminated"}, timeout_s=900.0, interval_s=15.0)


def _create_ready_environment(ctx: Any, app_name: str, extra_option_settings: list | None = None) -> str:
    eb = ctx.client("elasticbeanstalk")
    env_name = _eb_name(ctx, "env")
    stack = _pick_solution_stack(ctx)
    vpc_id, subnet_id = _create_public_vpc(ctx)
    instance_profile = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
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
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=_budget_s(ctx, 900.0), interval_s=2.0)
    return env_name


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


def _delete_vpc(ec2, vpc_id, timeout_s=600.0, interval_s=15.0):
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


def _wait_for_managed_action(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> dict:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        )
        for action in actions:
            if action.get("ActionType") == "InstanceRefresh":
                return action
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"a scheduled InstanceRefresh managed action on {env_name}: the run "
                           f"budget ended first; not graded")
    raise AssertionError(
        "AWS never scheduled an InstanceRefresh managed action for this environment within the poll "
        "window, even though InstanceRefreshEnabled does not depend on a pending platform update; "
        "would be closed by re-running or widening the window"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
