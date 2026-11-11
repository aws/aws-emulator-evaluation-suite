"""apply-managed-action-already-applied-rejected."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apply-managed-action-already-applied-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-applying a managed action that already left the Scheduled state is rejected with
    ManagedActionInvalidStateException, and no duplicate execution/history record is created,
    while the original (first) apply, the positive control, succeeded."""
    app_name = _create_app(ctx)
    start_time = _preferred_start_time(minutes_ahead=3)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": start_time},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
    ]
    env_name = _create_ready_environment(ctx, app_name, extra_option_settings=option_settings)

    # Managed instance refresh schedules a periodic InstanceRefresh action regardless of whether
    # a newer platform version exists, so the check creates the Scheduled action it applies
    # instead of waiting on a platform update that may never be pending. AWS's own scheduling
    # cadence, not this check's polling, dominates the wall clock.
    action = _wait_for_managed_action(ctx, env_name, timeout_s=1500.0)
    action_id = action["ActionId"]
    eb = ctx.client("elasticbeanstalk")

    # Positive control: applying a Scheduled action succeeds and the action leaves Scheduled.
    # ApplyEnvironmentManagedAction answers with the action's status at request time (still
    # Scheduled), so the transition is observed through DescribeEnvironmentManagedActions.
    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
    left_status = _wait_until_not_scheduled(ctx, env_name, action_id, timeout_s=300.0)

    # Negative: the action is no longer Scheduled, so applying it again must be rejected.
    code, message = _error(lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id))
    assert code == "ManagedActionInvalidStateException", (
        f"re-applying {action_id} after it left Scheduled (status={left_status!r}) should be "
        f"rejected with ManagedActionInvalidStateException, got {code!r} ({message!r})"
    )
    expected = "Managed action is scheduled to execute imminently, is going to be retried, or is already running"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected re-apply did not create a second live/history record.
    live = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
    live_count = sum(1 for a in live if a["ActionId"] == action_id)
    history = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
        "ManagedActionHistoryItems", []
    )
    history_count = sum(1 for i in history if i["ActionId"] == action_id)
    assert live_count + history_count == 1, (
        f"expected exactly one record of {action_id} across live+history, "
        f"got live={live_count} history={history_count}"
    )


# ===== helpers =====
_EB_PREFIX = "sim2real-eb-"


def _eb_name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_EB_PREFIX}{kind}-")


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
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
    ctx: Any, env_name: str, target_statuses: set[str], timeout_s: float = 900.0, interval_s: float = 15.0
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


def _terminate_environment(ctx: Any, env_name: str) -> None:
    eb = ctx.client("elasticbeanstalk")
    # A managed update the check applied may still be running; EB refuses to terminate an
    # environment mid-update, so let it settle first. All teardown waits together fit the 900 s cleanup budget.
    _wait_for_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=300.0, interval_s=2.0)
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # InvalidParameterValue is "No Environment found": already terminated; anything else raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_for_env_status(ctx, env_name, {"Terminated"}, timeout_s=300.0, interval_s=2.0)


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
    _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0, interval_s=15.0)
    return env_name


def _wait_for_managed_action(ctx: Any, env_name: str, timeout_s: float = 600.0, interval_s: float = 20.0) -> dict:
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
    raise AssertionError(
        "AWS never scheduled the InstanceRefresh managed action this check enabled within the poll "
        "window; InstanceRefreshEnabled does not depend on a pending platform update"
    )


def _wait_until_not_scheduled(ctx: Any, env_name: str, action_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    """Poll until ``action_id`` is no longer Scheduled; return its live status, or "history" once
    it has left the live list. Raise on timeout."""
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while True:
        live = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        match = [a for a in live if a["ActionId"] == action_id]
        if not match:
            return "history"
        if match[0]["Status"] != "Scheduled":
            return match[0]["Status"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the applied managed action {action_id} was still Scheduled after {timeout_s}s; "
                "the first apply (the positive control) did not take effect"
            )
        time.sleep(interval_s)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
