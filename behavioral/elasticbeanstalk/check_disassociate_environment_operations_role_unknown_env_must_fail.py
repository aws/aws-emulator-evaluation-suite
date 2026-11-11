"""disassociate-environment-operations-role-unknown-env-must-fail."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-environment-operations-role-unknown-env-must-fail"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateEnvironmentOperationsRole fails with InvalidParameterValue for a nonexistent
    environment and creates no record; on a real environment with no role it is a no-op."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    bogus_env_name = ctx.unique_name("sim2real-eb-ghost-")
    code, message = _error(
        lambda: eb.disassociate_environment_operations_role(EnvironmentName=bogus_env_name)
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code} ({message!r})"
    expected = f"No Environment found for EnvironmentName = '{bogus_env_name}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the bogus name never corresponds to a real environment record.
    ghost = eb.describe_environments(EnvironmentNames=[bogus_env_name], IncludeDeleted=False)[
        "Environments"
    ]
    assert ghost == [], f"unexpected environment materialized for a bogus name: {ghost}"

    # Positive control: the same operation succeeds against a real, freshly created environment.
    tag = [{"Key": "sim2real", "Value": "eb-disassociate-unknown-env"}]
    app_name = ctx.unique_name("sim2real-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    stack = next((s for s in stacks if "Amazon Linux" in s), stacks[0])

    vpc_id, subnet_id = _create_public_vpc(ctx)
    instance_profile = _create_eb_instance_profile(ctx, iam)
    service_role_arn = _create_eb_service_role(ctx, iam)

    env_name = ctx.unique_name("sim2real-eb-env-")
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=[
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role_arn},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            *_vpc_options(vpc_id, subnet_id),
        ],
        Tags=tag,
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(eb, env_name))
    _wait_env_ready(eb, env_name)

    # Must not raise -- disassociating when no operations role is set is a valid no-op.
    eb.disassociate_environment_operations_role(EnvironmentName=env_name)

    # And the real environment record is untouched by the earlier rejected call on the bogus name.
    real = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
    assert len(real) == 1 and real[0]["EnvironmentName"] == env_name, (
        f"expected exactly one environment named {env_name!r}, got {real!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
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


def _create_eb_instance_profile(ctx, iam):
    role_name = ctx.unique_name("sim2real-eb-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)

    def _cleanup():
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


def _create_eb_service_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-eb-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup():
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


def _wait_env_status(eb, env_name, statuses, timeout_s=900.0, interval_s=15.0, include_deleted=False):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=include_deleted)[
            "Environments"
        ]
        last = envs[0] if envs else None
        if last is not None and last["Status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses} within {timeout_s}s (last={last!r})")


def _wait_env_ready(eb, env_name, timeout_s=900.0, interval_s=15.0):
    _wait_env_status(eb, env_name, {"Ready"}, timeout_s=timeout_s, interval_s=interval_s)


def _terminate_and_wait(eb, env_name):
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # InvalidParameterValue is "No Environment found": already terminated; anything else raises.
        if exc.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    _wait_env_status(eb, env_name, {"Terminated"}, timeout_s=600.0, interval_s=2.0, include_deleted=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
