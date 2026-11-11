"""create-capacity-provider-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-capacity-provider-duplicate-name-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider rejects a name collision even when the underlying ASG is valid and distinct."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    subnet_id = _private_subnet(ctx)

    ami_id = _latest_al2023_ami(ctx)

    lt_name = ctx.unique_name("sim2real-ecs-cpdup-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-ecs-cpdup-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"
    ]

    # A second, distinct ASG so the retry below collides purely on *name*, not on ASG reuse
    # (reusing the same ASG ARN across capacity providers is itself rejected as a separate,
    # distinct error -- ClientException "already being used by another capacity provider").
    asg2_name = ctx.unique_name("sim2real-ecs-cpdup-asg2-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg2_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg2_name, ForceDelete=True))
    asg2_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg2_name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"
    ]

    cp_name = ctx.unique_name("sim2real-ecs-cpdup-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 80,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 10,
            },
        },
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )["capacityProvider"]
    ctx.on_cleanup(lambda: _delete_cp(ecs, cp_name))
    _wait_cp_active(ecs, cp_name)

    # Attempt to reuse the same name against a *different* ASG -- must fail purely on the
    # name collision, not on ASG reuse.
    code, message = _error(
        lambda: ecs.create_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={
                "autoScalingGroupArn": asg2_arn,
                "managedScaling": {
                    "status": "ENABLED",
                    "targetCapacity": 50,
                    "minimumScalingStepSize": 1,
                    "maximumScalingStepSize": 10,
                },
            },
        )
    )
    if code != "ClientException":
        raise AssertionError(f"expected ClientException on the name-collision retry, got {code!r}")
    assert message == (
        "The specified capacity provider already exists. To change the configuration of an existing "
        "capacity provider, update the capacity provider."
    ), f"unexpected message: {message!r}"

    # Effect absent: the original provider's config was not overwritten.
    described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    assert described["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"] == 80, (
        "the original capacity provider's managedScaling config changed despite the rejected duplicate-name create"
    )

    # Positive control: a distinct name against the same ASG succeeds.
    other_name = ctx.unique_name("sim2real-ecs-cpdup-ok-")
    good = ecs.create_capacity_provider(
        name=other_name,
        autoScalingGroupProvider={"autoScalingGroupArn": asg2_arn},
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )["capacityProvider"]
    ctx.on_cleanup(lambda: _delete_cp(ecs, other_name))
    assert good["name"] == other_name, (
        f"positive control: expected the distinct-name create to succeed as {other_name!r}, got {good['name']!r}"
    )

    # Terminal read: an independent DescribeCapacityProviders call, not the create response,
    # confirms the positive control actually took effect at the destination.
    _wait_cp_active(ecs, other_name)
    listed = ecs.describe_capacity_providers(capacityProviders=[other_name])["capacityProviders"]
    assert listed and listed[0]["status"] == "ACTIVE", (
        f"positive control: expected an independent describe of {other_name!r} to show ACTIVE, got {listed!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _private_subnet(ctx):
    """A subnet in a VPC this check creates. The zero-capacity Auto Scaling group placed in
    it launches no instance, so the subnet never holds an ENI and deletes cleanly."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return param["Parameter"]["Value"]


def _wait_cp_active(ecs, name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        described = ecs.describe_capacity_providers(capacityProviders=[name])["capacityProviders"]
        if described:
            last = described[0]["status"]
            if last == "ACTIVE":
                return
        time.sleep(3)
    raise AssertionError(f"capacity provider {name} never became ACTIVE (last status={last!r})")


def _delete_cp(ecs, name):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_capacity_provider(capacityProvider=name)
    except ClientError as exc:
        # the run may have failed before the capacity provider existed
        if exc.response["Error"]["Code"] != "ClientException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
