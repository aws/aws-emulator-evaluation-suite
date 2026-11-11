"""predictive-scaling-forecast-empty-before-data-exists."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-empty-before-data-exists"
GROUP = "data-plane"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPredictiveScalingForecast on a fresh ForecastOnly policy returns well-formed forecasts.

    Load and capacity points lie inside the window, Values align with Timestamps and are NaN or
    non-negative, and two back-to-back calls report the same timestamp grid.
    """
    asgc = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": lt_name}]}],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"]))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"]},
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        AvailabilityZones=[_first_az(ctx)],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    policy_name = ctx.unique_name("sim2real-behav-predpolicy-")
    asgc.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": 70.0,
                    "PredefinedMetricPairSpecification": {"PredefinedMetricType": "ASGCPUUtilization"},
                }
            ],
            "Mode": "ForecastOnly",
        },
    )
    ctx.on_cleanup(lambda: asgc.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name))

    now = datetime.now(timezone.utc)
    start, end = now, now + timedelta(days=2)

    # Docs state a minimum of 24h of CloudWatch history is needed for an *initial* forecast,
    # but real AWS answers GetPredictiveScalingForecast immediately -- either with an empty
    # forecast or a well-formed one. Either way it must never fabricate a nonsensical
    # (negative) load/capacity value, and every point it does return must stay inside the
    # requested window. Two back-to-back calls must also agree on the timestamps offered --
    # the forecast's hourly time grid is stable even if the underlying model refines its
    # numeric estimate between calls.
    resp1 = asgc.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name, PolicyName=policy_name, StartTime=start, EndTime=end
    )
    resp2 = asgc.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name, PolicyName=policy_name, StartTime=start, EndTime=end
    )

    load_forecasts_1 = resp1["LoadForecast"]
    load_forecasts_2 = resp2["LoadForecast"]
    assert len(load_forecasts_1) == 1, f"expected one load forecast entry (one metric spec), got {load_forecasts_1}"
    assert len(load_forecasts_2) == 1, f"expected one load forecast entry (one metric spec), got {load_forecasts_2}"

    _assert_sane(load_forecasts_1[0]["Timestamps"], load_forecasts_1[0]["Values"], start, end)
    _assert_sane(load_forecasts_2[0]["Timestamps"], load_forecasts_2[0]["Values"], start, end)
    assert load_forecasts_1[0]["Timestamps"] == load_forecasts_2[0]["Timestamps"], (
        "expected identical, back-to-back GetPredictiveScalingForecast calls for the same "
        "window to report the same hourly timestamp grid"
    )

    cap1 = resp1["CapacityForecast"]
    cap2 = resp2["CapacityForecast"]
    _assert_sane(cap1["Timestamps"], cap1["Values"], start, end)
    _assert_sane(cap2["Timestamps"], cap2["Values"], start, end)
    assert cap1["Timestamps"] == cap2["Timestamps"], (
        "expected identical, back-to-back GetPredictiveScalingForecast calls for the same "
        "window to report the same hourly timestamp grid for the capacity forecast"
    )


def _assert_sane(timestamps, values, start, end) -> None:
    assert len(timestamps) == len(values), (
        f"Timestamps/Values length mismatch: {len(timestamps)} vs {len(values)}"
    )
    for ts in timestamps:
        assert start <= ts < end, f"forecast timestamp {ts} fell outside requested window [{start}, {end})"
    for v in values:
        assert math.isnan(v) or v >= 0, f"forecast value {v} is negative, which is never a sane load/capacity estimate"


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
