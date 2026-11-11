"""create-capacity-provider-duplicate-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-capacity-provider-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider with the name of an ACTIVE provider is refused ClientException with
    the exact message, even for a different real Auto Scaling group, and the original stays
    ACTIVE on its own group."""
    ecs = ctx.client("ecs")
    asg1_arn, _ = _create_zero_capacity_asg(ctx)
    asg2_arn, _ = _create_zero_capacity_asg(ctx)

    cp_name = ctx.unique_name("sim2real-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"autoScalingGroupArn": asg1_arn, "managedTerminationProtection": "DISABLED"},
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))

    code, message = _error(lambda: ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"autoScalingGroupArn": asg2_arn, "managedTerminationProtection": "DISABLED"},
    ))
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected_message = (
        "The specified capacity provider already exists. To change the configuration of an "
        "existing capacity provider, update the capacity provider."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent + positive control (same describe call): the ORIGINAL capacity
    # provider is untouched by the rejected second create -- still ACTIVE and still
    # pointing at the first Auto Scaling group, not the second.
    cp = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    assert cp["status"] == "ACTIVE"
    assert cp["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg1_arn


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to create a zero-capacity Auto Scaling group fixture")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to create a zero-capacity Auto Scaling group fixture")
    return subnets[0]["SubnetId"]


def _create_zero_capacity_asg(ctx):
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ssm = ctx.client("ssm")
    subnet_id = _default_subnet(ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]

    lt_name = ctx.unique_name("sim2real-ecs-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-ecs-asg-")
    # MinSize=MaxSize=DesiredCapacity=0: the ASG exists (and gets a real ARN) but never
    # launches an EC2 instance, so this fixture is free.
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        NewInstancesProtectedFromScaleIn=True,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    return groups[0]["AutoScalingGroupARN"], asg_name


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
