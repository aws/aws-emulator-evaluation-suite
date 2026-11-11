"""delete-application-with-running-environment-must-fail."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-application-with-running-environment-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_STACK_CACHE = []

def _solution_stack(eb):
    """A usable SolutionStackName, preferring a current AL2023 Docker/Python stack."""
    if not _STACK_CACHE:
        _STACK_CACHE.extend(eb.list_available_solution_stacks().get("SolutionStacks") or [])
    stacks = list(_STACK_CACHE)
    if not stacks:
        raise AssertionError("No solution stacks available from ListAvailableSolutionStacks")
    preferred = (
        [s for s in stacks if "Amazon Linux 2023" in s and "running Docker" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
        or [s for s in stacks if "Amazon Linux 2023" in s]
        or [s for s in stacks if "running Docker" in s]
    )
    return (preferred or stacks)[0]


def _ensure_env_iam(ctx):
    """Create the instance profile + service role an EB environment needs, registering LIFO
    teardown, and return (instance_profile, service_role). Memoized on ctx so an
    env-creating check provisions IAM once."""
    if hasattr(ctx, "_eb_iam"):
        return ctx._eb_iam
    iam = ctx.client("iam")

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))
        return True

    ec2_role = ctx.unique_name("sim2real-behav-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-service-role-")
    profile = ctx.unique_name("sim2real-behav-eb-ec2-profile-")
    ec2_ok = _create_role(
        ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"]
    )
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            [
                "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
            ],
        )
        else None
    )
    iam.create_instance_profile(InstanceProfileName=profile, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    )
    instance_profile = profile if ec2_ok else None
    # IAM is eventually consistent; poll its own read path (a lower bound on the
    # visibility EB's control plane needs) instead of guessing a fixed delay.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            if instance_profile:
                iam.get_instance_profile(InstanceProfileName=instance_profile)
            if service_role:
                iam.get_role(RoleName=service_role)
            break
        except Exception:  # noqa: BLE001
            time.sleep(2.0)
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _env_option_settings(ctx):
    """Baseline option settings that make a single-instance environment launch."""
    instance_profile, service_role = _ensure_env_iam(ctx)
    if not hasattr(ctx, "_eb_vpc"):
        ctx._eb_vpc = _create_public_vpc(ctx)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        *_vpc_options(*ctx._eb_vpc),
    ]
    if instance_profile:
        settings.append(
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile}
        )
    if service_role:
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
        )
        settings.append(
            {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"}
        )
    return settings


def _launch_environment(ctx, eb, app_name, **kwargs):
    """Create an environment with the baseline (IAM-aware) option settings merged under any
    caller-supplied OptionSettings; register TerminateEnvironment teardown."""
    env_name = kwargs.pop("EnvironmentName", None) or ctx.unique_name("sim2real-behav-eb-env-")
    if "SolutionStackName" not in kwargs and "PlatformArn" not in kwargs and "TemplateName" not in kwargs:
        kwargs["SolutionStackName"] = _solution_stack(eb)
    merged = {(o["Namespace"], o["OptionName"]): o for o in _env_option_settings(ctx)}
    for o in kwargs.pop("OptionSettings", []):
        merged[(o["Namespace"], o["OptionName"])] = o
    kwargs["OptionSettings"] = list(merged.values())
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": "true"}])
    resp = eb.create_environment(ApplicationName=app_name, EnvironmentName=env_name, **kwargs)
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    return resp


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


def _wait_env_status(ctx, eb, app_name, env_name, terminal_statuses, timeout_s=900.0, interval_s=15.0):
    """Poll DescribeEnvironments until env_name reaches one of terminal_statuses; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(
            ApplicationName=app_name, EnvironmentNames=[env_name], IncludeDeleted=False
        )["Environments"]
        if envs:
            last = envs[0]["Status"]
            if last in terminal_statuses:
                return envs[0]
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {terminal_statuses}; last status={last!r}")


def _wait_application_gone(ctx, eb, app_name, timeout_s=900.0, interval_s=5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
        if not apps:
            return
        time.sleep(interval_s)
    raise AssertionError(f"application {app_name} was never removed after forced DeleteApplication")


def _safe_delete_application(eb, app_name) -> None:
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplication must refuse to delete an application with a running (Ready)
    environment unless TerminateEnvByForce is set; the identical call then succeeds
    once the flag is set."""
    eb = ctx.client("elasticbeanstalk")

    # Positive control: DeleteApplication succeeds outright on an application with no
    # environment at all, ruling out "DeleteApplication always fails without
    # TerminateEnvByForce" as an alternative explanation for the rejection asserted below.
    control_app = ctx.unique_name("sim2real-behav-eb-ctrl-")
    eb.create_application(ApplicationName=control_app, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=control_app: _safe_delete_application(eb, _n))
    eb.delete_application(ApplicationName=control_app)
    _wait_application_gone(ctx, eb, control_app, timeout_s=60.0)

    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: _safe_delete_application(eb, _n))

    resp = _launch_environment(ctx, eb, app_name)
    env_name = resp["EnvironmentName"]
    assert resp["Status"] == "Launching", f"expected a freshly created environment to start Launching, got {resp['Status']!r}"
    _wait_env_status(ctx, eb, app_name, env_name, {"Ready"}, timeout_s=1200.0)

    code, message = _err(
        lambda: eb.delete_application(
            ApplicationName=app_name, TerminateEnvByForce=False
        )
    )
    assert code == "InvalidParameterValue", (
        f"deleting an application that still has a running environment without "
        f"TerminateEnvByForce must fail with InvalidParameterValue, got {code!r} ({message!r})"
    )
    expected = (
        f"Unable to delete application {app_name} because it has a version that is "
        f"deployed to a running environment."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described = eb.describe_applications(ApplicationNames=[app_name])
    assert len(described["Applications"]) == 1, (
        f"application must still exist after the refused delete, found {described['Applications']}"
    )

    envs = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    assert len(envs) == 1 and envs[0]["Status"] == "Ready", (
        f"expected environment {env_name} to remain Ready after the refused delete, found {envs}"
    )

    # Restore + identical-call-now-succeeds beat: the same delete succeeds once
    # TerminateEnvByForce=True is set, and the application is verifiably gone after.
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)
    _wait_application_gone(ctx, eb, app_name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
