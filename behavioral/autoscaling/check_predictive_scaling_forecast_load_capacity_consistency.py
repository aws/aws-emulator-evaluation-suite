"""predictive-scaling-forecast-load-capacity-consistency."""
from __future__ import annotations

import datetime
import math

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-load-capacity-consistency"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CapacityForecast and LoadForecast share one timestamp grid and are NaN at the same points;
    a fresh group has no CloudWatch history, so every point of both is NaN."""
    autoscaling = ctx.client("autoscaling")
    az = _first_az(ctx)
    lt_name = _create_dummy_launch_template(ctx)
    asg_name = _create_empty_asg(ctx, lt_name, az)
    policy_name = ctx.unique_name("sim2real-predsc-")
    target_value = 50.0

    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": target_value,
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

    load_forecasts = resp.get("LoadForecast") or []
    capacity_forecast = resp.get("CapacityForecast") or {}
    assert len(load_forecasts) == 1, (
        f"expected exactly one LoadForecast entry for the single metric "
        f"specification, got {load_forecasts!r}"
    )
    load_values = load_forecasts[0].get("Values") or []
    cap_values = capacity_forecast.get("Values") or []
    assert len(load_values) == len(cap_values) > 0, (
        "GetPredictiveScalingForecast returned an empty or length-mismatched "
        f"LoadForecast/CapacityForecast series: load={load_values!r} cap={cap_values!r}"
    )
    assert load_forecasts[0].get("Timestamps") == capacity_forecast.get("Timestamps"), (
        "LoadForecast and CapacityForecast must report the same hourly timestamp "
        f"grid: load={load_forecasts[0].get('Timestamps')!r} "
        f"cap={capacity_forecast.get('Timestamps')!r}"
    )

    # With no CloudWatch history AWS fills unknown forecast points with NaN. Load and capacity
    # derive from the same data, so a point is NaN in both series or in neither.
    for load, capacity in zip(load_values, cap_values):
        assert math.isnan(load) == math.isnan(capacity), (
            "load/capacity forecast NaN-placeholder state diverged at the same "
            f"timestamp: load={load!r} capacity={capacity!r}"
        )

    finite_pairs = [
        (load, capacity)
        for load, capacity in zip(load_values, cap_values)
        if not (math.isnan(load) and math.isnan(capacity))
    ]
    assert not finite_pairs, (
        f"a group with no CloudWatch history must forecast NaN at every point, got "
        f"{len(finite_pairs)} real (load, capacity) pairs: {finite_pairs[:5]}"
    )


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

