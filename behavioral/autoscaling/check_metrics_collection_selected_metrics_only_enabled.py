"""metrics-collection-selected-metrics-only-enabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-collection-selected-metrics-only-enabled"
GROUP = "telemetry"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableMetricsCollection with a Metrics subset enables exactly that subset, and disabling one
    removes only it. An unknown metric name is rejected with ValidationError and enables nothing."""
    asgc = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"]))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"]},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    catalog = {m["Metric"] for m in asgc.describe_metric_collection_types()["Metrics"]}
    selected = {"GroupMinSize", "GroupMaxSize"}
    assert selected < catalog, "test assumes the selected subset is a strict subset of the full catalog"

    def _enabled_metric_names():
        return {
            e["Metric"]
            for e in asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0][
                "EnabledMetrics"
            ]
        }

    asgc.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Metrics=sorted(selected), Granularity="1Minute"
    )
    enabled = _enabled_metric_names()
    assert enabled == selected, f"expected only {selected} enabled, got {enabled}"

    asgc.disable_metrics_collection(AutoScalingGroupName=asg_name, Metrics=["GroupMinSize"])
    remaining = _enabled_metric_names()
    assert remaining == {"GroupMaxSize"}, f"expected only GroupMaxSize to remain enabled, got {remaining}"

    asgc.disable_metrics_collection(AutoScalingGroupName=asg_name)
    assert _enabled_metric_names() == set()

    # An unknown metric name must be rejected, not silently accepted as a no-op enable.
    try:
        result = asgc.enable_metrics_collection(
            AutoScalingGroupName=asg_name,
            Metrics=["NotARealMetricName"],
            Granularity="1Minute",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"EnableMetricsCollection with an unknown metric name SUCCEEDED: {result!r}")
    assert code == "ValidationError", f"expected ValidationError for an unknown metric name, got {code}"
    expected_message = (
        "Valid metrics collection types are: [GroupMinSize, GroupMaxSize, GroupDesiredCapacity, "
        "GroupInServiceInstances, GroupInServiceCapacity, GroupPendingInstances, GroupPendingCapacity, "
        "GroupTerminatingInstances, GroupTerminatingCapacity, GroupTerminatingRetainedInstances, "
        "GroupTerminatingRetainedCapacity, GroupStandbyInstances, GroupStandbyCapacity, "
        "GroupTotalInstances, GroupTotalCapacity, WarmPoolMinSize, WarmPoolDesiredCapacity, "
        "WarmPoolPendingCapacity, WarmPoolPendingRetainedCapacity, WarmPoolTerminatingCapacity, "
        "WarmPoolTerminatingRetainedCapacity, WarmPoolWarmedCapacity, WarmPoolTotalCapacity, "
        "GroupAndWarmPoolDesiredCapacity, GroupAndWarmPoolTotalCapacity]."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _enabled_metric_names() == set(), "an invalid enable call must not leave any metric active"


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
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
