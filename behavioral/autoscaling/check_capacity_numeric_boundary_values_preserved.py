"""capacity-numeric-boundary-values-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "capacity-numeric-boundary-values-preserved"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Large boundary values for MinSize/MaxSize/DesiredCapacity read back exactly from
    DescribeAutoScalingGroups; DesiredCapacity stays at MinSize so no capacity launches."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    min_size = 0
    max_size = 2147483647  # int32 max: the classic boundary for a naive 32-bit field
    desired_capacity = 0

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired_capacity,
        AvailabilityZones=[az],
        Tags=[
            {
                "Key": "sim2real-behav",
                "Value": asg_name,
                "PropagateAtLaunch": False,
                "ResourceType": "auto-scaling-group",
                "ResourceId": asg_name,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["MinSize"] == min_size, f"MinSize truncated/rounded: expected {min_size}, got {group['MinSize']}"
    assert group["MaxSize"] == max_size, f"MaxSize truncated/rounded: expected {max_size}, got {group['MaxSize']}"
    assert group["DesiredCapacity"] == desired_capacity, (
        f"DesiredCapacity truncated/rounded: expected {desired_capacity}, got {group['DesiredCapacity']}"
    )
    assert isinstance(group["MaxSize"], int) and not isinstance(group["MaxSize"], bool), (
        f"MaxSize downcast to a non-int type: got {group['MaxSize']!r} ({type(group['MaxSize'])!r})"
    )


def _first_available_az(ec2, *, ctx) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    return zones[0]["ZoneName"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


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
