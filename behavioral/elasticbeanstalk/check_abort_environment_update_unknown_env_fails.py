"""abort-environment-update-unknown-env-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "abort-environment-update-unknown-env-fails"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']


def _err(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AbortEnvironmentUpdate fails with InvalidParameterValue for an unknown environment and for a
    Ready one with no update in progress; aborting an in-progress update cancels it unapplied."""
    eb = ctx.client("elasticbeanstalk")

    # Always-invalid-input negative: this environment name can never come to exist.
    unknown_env = ctx.unique_name("sim2real-eb-env-absent-")
    code, message = _err(lambda: eb.abort_environment_update(EnvironmentName=unknown_env))
    assert code == "InvalidParameterValue", (
        f"AbortEnvironmentUpdate on a nonexistent environment must fail with "
        f"InvalidParameterValue, got {code!r} ({message!r})"
    )
    expected = f"No Environment found for EnvironmentName = '{unknown_env}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")[:40]
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    vpc_id, subnet_id = _create_public_vpc(ctx)
    instance_profile, service_role = _ensure_env_iam(ctx)
    option_settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        *_vpc_options(vpc_id, subnet_id),
    ]
    if instance_profile:
        option_settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        option_settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )

    stack = _pick_solution_stack(eb)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=option_settings,
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=1500)

    # No update in progress: AbortEnvironmentUpdate has nothing to cancel and is rejected,
    # not silently accepted as a no-op.
    idle_code, idle_message = _err(lambda: eb.abort_environment_update(EnvironmentName=env_name))
    assert idle_code == "InvalidParameterValue", (
        f"AbortEnvironmentUpdate against a Ready environment with no update in progress must "
        f"fail with InvalidParameterValue, got {idle_code!r} ({idle_message!r})"
    )
    expected_idle = (
        f"Environment named {env_name} is in an invalid state for this operation. "
        f"Must be pending deployment."
    )
    assert idle_message == expected_idle, (
        f"expected message {expected_idle!r}, got {idle_message!r}"
    )
    settled = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert settled["Status"] == "Ready", (
        f"a rejected, idle AbortEnvironmentUpdate must not move the environment out of Ready, "
        f"got {settled['Status']!r}"
    )

    # Positive control: an update aborted while still in progress really is cancelled, so the
    # rejections above are state-specific rather than a blanket refusal.
    update_resp = eb.update_environment(
        EnvironmentName=env_name,
        OptionSettings=[
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": "FIDELITY_TEST_VAR",
                "Value": "should-not-apply",
            }
        ],
    )
    assert update_resp["Status"] == "Updating", (
        f"UpdateEnvironment on a Ready environment must start updating, got {update_resp['Status']!r}"
    )
    eb.abort_environment_update(EnvironmentName=env_name)

    final = _wait_env_status(eb, env_name, {"Ready"}, timeout_s=600)
    assert final["Status"] == "Ready", (
        f"the aborted environment must settle back to Ready, got {final['Status']!r}"
    )
    leaked = [
        o
        for o in eb.describe_configuration_settings(
            ApplicationName=app_name, EnvironmentName=env_name
        )["ConfigurationSettings"][0]["OptionSettings"]
        if o["OptionName"] == "FIDELITY_TEST_VAR"
    ]
    assert leaked == [], (
        "a genuinely cancelled update must not apply the option setting it was carrying"
    )


def _terminate_and_wait(eb, env_name, timeout_s=900.0, interval_s=15.0):
    """Terminate the environment and wait until it is gone, so the VPC teardown can follow."""
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"environment {env_name} not terminated within {timeout_s}s")
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


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs,
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades to
    (None, None) if IAM is unreachable, letting the service apply its own defaults."""
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return (None, None)

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        except Exception as exc:  # noqa: BLE001 -- already-exists is fine
            if "EntityAlreadyExists" not in str(exc):
                return False
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))
            except Exception:  # noqa: BLE001
                pass
        return True

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-service-role-")
    profile = ctx.unique_name("sim2real-eb-ec2-profile-")
    ec2_ok = _create_role(
        ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"]
    )
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"],
        )
        else None
    )
    instance_profile = None
    if ec2_ok:
        made = True
        try:
            iam.create_instance_profile(InstanceProfileName=profile)
            ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
        except Exception as exc:  # noqa: BLE001
            if "EntityAlreadyExists" not in str(exc):
                made = False
        if made:
            try:
                iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                ctx.on_cleanup(
                    lambda: iam.remove_role_from_instance_profile(
                        InstanceProfileName=profile, RoleName=ec2_role
                    )
                )
            except Exception:  # noqa: BLE001
                pass
            instance_profile = profile
    # IAM is eventually consistent: bounded poll until the new instance profile itself reads
    # back consistently, rather than a blind sleep with no stated deadline.
    if instance_profile:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            try:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
                break
            except Exception:  # noqa: BLE001
                time.sleep(3)
    return (instance_profile, service_role)


def _pick_solution_stack(eb) -> str:
    """A usable SolutionStackName, preferring a fast-launching AL2023 Docker/Python stack over
    the much slower-to-provision Java/Tomcat platforms."""
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    preferred = (
        [s for s in stacks if "Amazon Linux 2023" in s and "running Docker" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "Windows" not in s]
        or [s for s in stacks if "Windows" not in s]
    )
    return (preferred or stacks)[0]


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    events = []
    try:
        events = [
            f"{e['EventDate']} {e['Severity']}: {e['Message']}"
            for e in eb.describe_events(EnvironmentName=env_name, MaxRecords=20).get("Events", [])
        ]
    except Exception as exc:  # noqa: BLE001 -- diagnostics only, never mask the real failure
        events = [f"<describe_events failed: {exc}>"]
    raise AssertionError(
        f"environment {env_name} never reached {statuses}; last={last}\nrecent events:\n"
        + "\n".join(events)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
