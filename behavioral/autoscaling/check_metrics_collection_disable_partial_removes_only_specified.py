"""metrics-collection-disable-partial-removes-only-specified."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metrics-collection-disable-partial-removes-only-specified"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableMetricsCollection given a specific metric list removes only those metrics
    and leaves the other previously enabled metrics intact."""
    autoscaling = ctx.client("autoscaling")
    az = _first_az(ctx)
    lt_name = _create_dummy_launch_template(ctx)
    asg_name = _create_empty_asg(ctx, lt_name, az)

    autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name,
        Granularity="1Minute",
        Metrics=["GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity"],
    )
    before = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    before_enabled = {m["Metric"] for m in before["EnabledMetrics"]}
    assert before_enabled == {
        "GroupMinSize",
        "GroupMaxSize",
        "GroupDesiredCapacity",
    }, f"expected all 3 enabled metrics after EnableMetricsCollection, got {before_enabled}"

    autoscaling.disable_metrics_collection(
        AutoScalingGroupName=asg_name, Metrics=["GroupMaxSize"]
    )

    after = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    remaining = {m["Metric"] for m in after["EnabledMetrics"]}
    assert remaining == {"GroupMinSize", "GroupDesiredCapacity"}, remaining


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


def _create_dummy_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_empty_asg(
    ctx, lt_name: str, az: str, min_size: int = 0, max_size: int = 0, desired: int = 0
) -> str:
    autoscaling = ctx.client("autoscaling")
    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


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
