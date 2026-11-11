"""set-desired-capacity-negative-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-desired-capacity-negative-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity with a negative integer is rejected as an
    out-of-range value, distinct from the exceeds-max rejection."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    az = _get_az(ctx)
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=3,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )

    # Break exactly one thing: a negative DesiredCapacity.
    code, message = _error(
        lambda: autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=-1)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "New SetDesiredCapacity value -1 is negative.", (
        f"unexpected ValidationError message: {message!r}"
    )

    # Effect absent: DesiredCapacity is unchanged.
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 0, "DesiredCapacity must not have been mutated"

    # Positive control: the same call succeeds with a valid, non-negative value.
    autoscaling.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=0)
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 0


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _get_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
