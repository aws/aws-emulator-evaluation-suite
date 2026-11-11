"""predictive-scaling-forecast-timestamp-value-alignment."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-timestamp-value-alignment"
GROUP = "ordering"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPredictiveScalingForecast returns strictly increasing Load/CapacityForecast Timestamps,
    each non-empty and length-aligned with its Values, even for a fresh policy with no history.
    The docs' >=24h history note governs forecast quality, not whether a grid is returned."""
    autoscaling = ctx.client("autoscaling")
    az = _first_az(ctx)
    lt_name = _create_dummy_launch_template(ctx)
    asg_name = _create_empty_asg(ctx, lt_name, az)
    policy_name = ctx.unique_name("sim2real-predsc-")

    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": 50.0,
                    "PredefinedMetricPairSpecification": {
                        "PredefinedMetricType": "ASGCPUUtilization"
                    },
                }
            ],
            "Mode": "ForecastOnly",
        },
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_policy(
            AutoScalingGroupName=asg_name, PolicyName=policy_name
        )
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    resp = autoscaling.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        StartTime=now - datetime.timedelta(hours=24),
        EndTime=now + datetime.timedelta(hours=24),
    )

    load_forecasts = resp["LoadForecast"]
    assert len(load_forecasts) >= 1, (
        "GetPredictiveScalingForecast returned no LoadForecast entry at all for a "
        "policy with one metric specification"
    )
    capacity_forecast = resp["CapacityForecast"]

    load_timestamps = load_forecasts[0]["Timestamps"]
    load_values = load_forecasts[0]["Values"]
    assert len(load_timestamps) == len(load_values) > 0, (
        "LoadForecast Timestamps/Values must be non-empty and length-aligned, even "
        "immediately after policy creation with no CloudWatch history"
    )
    for earlier, later in zip(load_timestamps, load_timestamps[1:]):
        assert earlier < later, (earlier, later)

    cap_timestamps = capacity_forecast["Timestamps"]
    cap_values = capacity_forecast["Values"]
    assert len(cap_timestamps) == len(cap_values) > 0, (
        "CapacityForecast Timestamps/Values must be non-empty and length-aligned, "
        "even immediately after policy creation with no CloudWatch history"
    )
    for earlier, later in zip(cap_timestamps, cap_timestamps[1:]):
        assert earlier < later, (earlier, later)


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
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
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
