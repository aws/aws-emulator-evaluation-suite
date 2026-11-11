"""asg-capacity-large-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "asg-capacity-large-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Large MinSize/MaxSize/DesiredCapacity values round-trip through Create/DescribeAutoScalingGroups
    with no overflow or floating-point precision loss."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    min_size = 0
    max_size = 999999999
    desired = 0  # keep at 0 so no real EC2 launches are attempted despite the huge MaxSize

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[_first_available_az(ec2, ctx=ctx)],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_available_az(ec2, ctx=ctx)]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["MinSize"] == min_size, (
        f"MinSize drifted: sent {min_size}, got {group['MinSize']!r}"
    )
    assert group["MaxSize"] == max_size, (
        f"MaxSize precision drifted: sent {max_size}, got {group['MaxSize']!r}"
    )
    assert group["DesiredCapacity"] == desired, (
        f"DesiredCapacity drifted: sent {desired}, got {group['DesiredCapacity']!r}"
    )
    assert isinstance(group["MaxSize"], int) and not isinstance(group["MaxSize"], bool), (
        f"MaxSize decoded as {type(group['MaxSize'])!r}, expected a plain int (not bool, not float)"
    )


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _first_available_az(ec2, *, ctx) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    return zones[0]["ZoneName"]


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
