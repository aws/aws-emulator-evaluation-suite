"""apply-environment-managed-action-unknown-action-id-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "apply-environment-managed-action-unknown-action-id-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ActionId that never existed is rejected with ElasticBeanstalkServiceException, distinct
    from ManagedActionInvalidStateException, and leaves pending actions and history unchanged."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-beh-app-")
    env_name = ctx.unique_name("sim2real-env-")[:40]
    bogus_action_id = str(uuid.uuid4())

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_application(eb, app_name))

    vpc_id, subnet_id = _create_public_vpc(ctx)
    instance_profile, service_role = _ensure_env_iam(ctx)

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:03:00"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            *_vpc_options(vpc_id, subnet_id),
        ],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    # The apply checks for a Ready environment with managed updates enabled before it looks at
    # the ActionId, so both are set up first.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(
        eb, env_name, {"Ready"}, timeout_s=900, interval_s=15,
        include_deleted=True, failure_statuses={"Terminated"},
    )

    # Positive control: describing managed actions for a Ready environment is a normal,
    # successful call. Capture the pending-action set so the rejection's terminal read can
    # prove the bogus apply left it untouched.
    before_ids = {
        a["ActionId"]
        for a in eb.describe_environment_managed_actions(EnvironmentName=env_name)["ManagedActions"]
    }

    code, message = _error_code_and_message(
        lambda: eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=bogus_action_id)
    )
    assert code == "ElasticBeanstalkServiceException", f"{code}: {message}"
    expected = "Managed update data not found for this environment."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Terminal read, independent of the rejected call: the pending-action set is unchanged,
    # and the bogus id never surfaces in the completed/failed action history either.
    after_ids = {
        a["ActionId"]
        for a in eb.describe_environment_managed_actions(EnvironmentName=env_name)["ManagedActions"]
    }
    assert after_ids == before_ids, (
        f"apply_environment_managed_action with an unknown ActionId must not change the "
        f"pending managed-action set, but it went from {before_ids!r} to {after_ids!r}"
    )

    history_ids = {
        h["ActionId"]
        for h in eb.describe_environment_managed_action_history(EnvironmentName=env_name)[
            "ManagedActionHistoryItems"
        ]
    }
    assert bogus_action_id not in history_ids, (
        f"a rejected apply of unknown ActionId {bogus_action_id!r} must not appear in "
        f"managed-action history, but it does: {history_ids!r}"
    )


# ===== helpers =====

_EB_EC2_POLICY_ARN = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
_EB_MANAGED_UPDATES_POLICY_ARN = "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"


def _create_role(ctx, iam, name, service, policy_arns):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))


def _ensure_env_iam(ctx) -> tuple[str, str]:
    """Create the instance profile and managed-updates service role the environment needs.

    The console creates defaults on first use, so a fresh account has neither."""
    iam = ctx.client("iam")
    ec2_role = ctx.unique_name("sim2real-behav-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-service-role-")
    profile_name = ctx.unique_name("sim2real-behav-eb-ec2-profile-")

    _create_role(ctx, iam, ec2_role, "ec2.amazonaws.com", [_EB_EC2_POLICY_ARN])
    _create_role(
        ctx, iam, svc_role, "elasticbeanstalk.amazonaws.com", [_EB_MANAGED_UPDATES_POLICY_ARN]
    )

    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=ec2_role
        )
    )
    _wait_instance_profile_visible(iam, profile_name)
    return profile_name, svc_role


def _wait_instance_profile_visible(iam, profile_name, timeout_s=30.0, interval_s=2.0):
    """IAM is eventually consistent: bound the wait for the just-created instance profile to
    become independently readable, rather than guessing a flat sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"instance profile {profile_name!r} never became visible within {timeout_s}s")


def _error_code_and_message(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks().get("SolutionStacks", [])
    for s in stacks:
        if "Windows" not in s:
            return s
    return stacks[0]


def _wait_env_status(
    eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=False,
    failure_statuses=frozenset(),
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)
        envs = resp.get("Environments", [])
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        if last is not None and last["Status"] in failure_statuses:
            events = eb.describe_events(EnvironmentName=env_name, Severity="ERROR").get("Events", [])
            reasons = [e.get("Message") for e in events]
            raise AssertionError(
                f"environment {env_name} reached terminal {last['Status']!r} while waiting for "
                f"{statuses}, health={last.get('Health')!r} healthStatus={last.get('HealthStatus')!r}, "
                f"error events={reasons!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _terminate_and_wait(eb, env_name):
    from botocore.exceptions import ClientError
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # InvalidParameterValue is "No Environment found": already terminated; anything else raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600, interval_s=2, include_deleted=True)


def _delete_application(eb, app_name):
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=False)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
