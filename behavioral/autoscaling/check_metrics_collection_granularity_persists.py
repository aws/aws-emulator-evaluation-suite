"""metrics-collection-granularity-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metrics-collection-granularity-persists"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After enabling a metric subset at a granularity and disabling one metric, EnabledMetrics shows
    exactly the remaining metrics at that granularity, drawn from DescribeMetricCollectionTypes."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    catalog = autoscaling.describe_metric_collection_types()
    available_metrics = [m["Metric"] for m in catalog["Metrics"]]
    available_granularities = [g["Granularity"] for g in catalog["Granularities"]]
    assert "1Minute" in available_granularities, (
        f"expected 1Minute in the catalog's granularities, got {available_granularities}"
    )
    assert len(available_metrics) >= 3, "need at least 3 known metrics to test a subset"
    chosen = available_metrics[:3]

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Granularity="1Minute", Metrics=chosen
    )
    ctx.on_cleanup(lambda: autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name))

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    enabled_after_enable = {m["Metric"]: m["Granularity"] for m in group["EnabledMetrics"]}
    assert set(enabled_after_enable) == set(chosen), (
        f"expected exactly {set(chosen)} enabled, got {set(enabled_after_enable)}"
    )
    assert all(g == "1Minute" for g in enabled_after_enable.values()), (
        f"expected every enabled metric at 1Minute granularity, got {enabled_after_enable}"
    )

    disabled_metric = chosen[0]
    autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name, Metrics=[disabled_metric])

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    enabled_after_disable = {m["Metric"]: m["Granularity"] for m in group["EnabledMetrics"]}
    expected_remaining = set(chosen[1:])
    assert set(enabled_after_disable) == expected_remaining, (
        f"expected remaining enabled metrics {expected_remaining}, got {set(enabled_after_disable)}"
    )
    assert all(g == "1Minute" for g in enabled_after_disable.values()), (
        f"expected the surviving metrics to keep their 1Minute granularity, got {enabled_after_disable}"
    )
    assert disabled_metric not in enabled_after_disable, (
        f"expected {disabled_metric} to be gone after DisableMetricsCollection, still in {enabled_after_disable}"
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
