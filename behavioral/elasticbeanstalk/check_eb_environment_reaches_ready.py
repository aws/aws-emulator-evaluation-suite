"""eb-environment-reaches-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eb-environment-reaches-ready"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_env(eb, env_name):
    """DescribeEnvironments for one name (IncludeDeleted); return the record or None."""
    envs = eb.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=True
    ).get("Environments") or []
    return envs[0] if envs else None


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
    """Create the instance profile + service role an EB environment needs, with LIFO teardown.

    Returns (instance_profile, service_role). Any IAM failure raises: an environment launched
    on the service's default principals is a different subject. Memoized on ctx so an
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
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real", "Value": "eb-environment-reaches-ready"}],
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-behav-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-service-role-")
    profile = ctx.unique_name("sim2real-behav-eb-ec2-profile-")
    _create_role(ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
    _create_role(
        svc_role,
        "elasticbeanstalk.amazonaws.com",
        [
            "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
            "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
        ],
    )
    iam.create_instance_profile(
        InstanceProfileName=profile,
        Tags=[{"Key": "sim2real", "Value": "eb-environment-reaches-ready"}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    )
    # IAM is eventually consistent: EB may not yet be able to see the new principals.
    # Rather than sleep blindly, `_launch_environment` retries CreateEnvironment itself
    # against a bounded deadline until the principals become visible.
    ctx._eb_iam = (profile, svc_role)
    return ctx._eb_iam


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


def _env_option_settings(ctx):
    """Baseline option settings that make a single-instance environment launch in a VPC the
    check owns, with principals the check owns."""
    instance_profile, service_role = _ensure_env_iam(ctx)
    vpc_id, subnet_id = _create_public_vpc(ctx)
    return [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
        *_vpc_options(vpc_id, subnet_id),
    ]


def _create_environment_with_retry(eb, *, timeout_s=90, interval_s=10, **kwargs):
    """CreateEnvironment, retrying on ClientError until timeout_s elapses.

    The IAM role/instance profile this environment references were just created;
    IAM is eventually consistent, so EB may reject the reference for a short window
    before it can see the new principals. Retrying the actual call that depends on
    that visibility (rather than sleeping blindly beforehand) bounds the wait to
    exactly as long as the propagation takes, and still fails loudly if the error
    is not propagation at all.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateEnvironment kept failing for {timeout_s}s (expected IAM role/instance-profile "
        f"propagation to resolve within that window): {last_exc}"
    )


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
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": "eb-environment-reaches-ready"}])
    resp = _create_environment_with_retry(
        eb, ApplicationName=app_name, EnvironmentName=env_name, **kwargs
    )
    ctx.on_cleanup(lambda: _terminate_if_present(eb, env_name))
    return resp


def _terminate_if_present(eb, env_name):
    """Teardown: TerminateEnvironment, tolerating only the not-found refusal of an environment
    the body already terminated."""
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "InvalidParameterValue" or "not found" not in err.get("Message", ""):
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment on a current Amazon Linux 2023 solution stack returns Launching on that stack, and the
    environment reaches Status Ready with Health Green or Yellow."""

    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-ready-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "eb-environment-reaches-ready"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    # A current 64bit AL2023 Docker/Python sample platform, resolved from
    # list_available_solution_stacks() and cached.
    stack = _solution_stack(eb)
    resp = _launch_environment(ctx, eb, app_name, SolutionStackName=stack)
    env_name = resp["EnvironmentName"]
    assert resp["Status"] == "Launching", (
        f"a newly created environment must start Launching, got {resp['Status']!r}"
    )
    assert resp["SolutionStackName"] == stack, (
        f"expected the environment to launch on {stack!r}, got {resp['SolutionStackName']!r}"
    )

    # Provisioning + booting the EC2 backend takes many minutes; wait for the
    # environment to finish and its sample app to report healthy.
    final = _poll_until(
        lambda: _describe_env(eb, env_name),
        lambda env: env is not None
        and env.get("Status") == "Ready"
        and env.get("Health") in ("Green", "Yellow"),
        timeout_s=1200,
        interval_s=20,
        description=f"EB environment {env_name} reaching Ready with healthy status",
    )
    assert final["Status"] == "Ready", final.get("Status")
    assert final["Health"] in ("Green", "Yellow"), final.get("Health")

    # --- Self-clean: terminate the environment, wait for it to actually finish winding down.
    # "Terminating" is a transient state — the underlying ASG/EC2 instance (and its auto-assigned
    # Elastic IP) can still be mid-teardown while it holds, so it must not be in the poll's
    # terminal set. Only "Terminated" (or the record disappearing outright) means those
    # resources are actually gone.
    eb.terminate_environment(EnvironmentName=env_name)
    _poll_until(
        lambda: _describe_env(eb, env_name),
        lambda env: env is None or env.get("Status") == "Terminated",
        timeout_s=600,
        interval_s=20,
        description=f"EB environment {env_name} reaching Terminated",
    )

    # Force-delete the application (removes any lingering terminating env too).
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
