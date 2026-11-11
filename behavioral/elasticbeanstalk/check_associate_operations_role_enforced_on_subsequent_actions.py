"""associate-operations-role-enforced-on-subsequent-actions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-operations-role-enforced-on-subsequent-actions"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After AssociateEnvironmentOperationsRole succeeds, DescribeEnvironments reflects the
    operations role; after DisassociateEnvironmentOperationsRole, the role is gone again."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    app_name = ctx.unique_name("sim2real-ebops-app-")
    env_name = _short_env_name(ctx, "ebops")
    role_name = ctx.unique_name("sim2real-eb-opsrole-")[-63:]

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    vpc_id, subnet_id = _create_public_vpc(ctx)
    instance_profile_name = _create_eb_instance_profile(ctx)
    service_role_arn = _create_eb_service_role(ctx)

    stack = _pick_solution_stack(ctx)

    def _create_env():
        eb.create_environment(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=stack,
            OptionSettings=[
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile_name},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                *_vpc_options(vpc_id, subnet_id),
            ],
            Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
        )

    # the instance profile and service role just created above can take a few seconds to
    # become usable by Elastic Beanstalk service-wide
    _retry_insufficient_privileges(_create_env, timeout_s=60.0)
    # Blocks until Terminated, and runs before the operations role's teardown (LIFO): Beanstalk
    # assumes that role to terminate, and deleting it first leaves the env unterminatable.
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"
    assert "OperationsRole" not in env, "freshly created environment should not have an operations role yet"

    # newly created IAM roles can take a few seconds to become assumable service-wide
    def _associate():
        eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=role_arn)

    _retry_insufficient_privileges(_associate, timeout_s=60.0)

    described = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0],
        lambda e: e.get("OperationsRole") == role_arn,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert described.get("OperationsRole") == role_arn, "OperationsRole not reflected after associate"

    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    described_after = _poll_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0],
        lambda e: not e.get("OperationsRole"),
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert not described_after.get("OperationsRole"), "OperationsRole still present after disassociate"


# ===== helpers =====
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


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _terminate_and_wait(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    """Disassociate any operations role, then terminate and wait for Terminated, re-issuing each
    call while an in-flight update (e.g. a just-made role association) rejects it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments", [])
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                if envs[0].get("OperationsRole"):
                    # Beanstalk terminates AS the operations role, which may lack the permissions to.
                    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
                else:
                    eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as exc:
                # An in-flight update answers InvalidParameterValue ("invalid state"): retry it; raise the rest.
                if exc.response["Error"]["Code"] not in ("InvalidParameterValue", "OperationInProgressFailure"):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s}s")


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 20.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last={last})")


_RETRYABLE_EVENTUAL_CONSISTENCY_CODES = ("InsufficientPrivilegesException", "InvalidParameterValue")


def _retry_insufficient_privileges(fn, *, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] not in _RETRYABLE_EVENTUAL_CONSISTENCY_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_eb_instance_profile(ctx) -> str:
    """The EC2 instances Elastic Beanstalk launches need an instance profile; a freshly
    provisioned account has none of the console's auto-created default roles, so this check
    creates its own rather than assuming `aws-elasticbeanstalk-ec2-role` already exists."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebops-ec2role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
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


def _create_eb_service_role(ctx) -> str:
    """Elastic Beanstalk needs a service role to manage the environment's resources on the
    caller's behalf; a freshly provisioned account has no `aws-elasticbeanstalk-service-role`,
    so this check creates its own."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebops-svcrole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )["Role"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
