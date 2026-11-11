"""get-predictive-scaling-forecast-server-computed."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-predictive-scaling-forecast-server-computed"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPredictiveScalingForecast returns a server-computed LoadForecast, CapacityForecast and
    UpdateTime with datapoints inside the requested window, not an echo of StartTime/EndTime."""
    asg = ctx.client("autoscaling")
    lt_name = _create_launch_template(ctx, ami_id=_get_al2_ami(ctx))
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        AvailabilityZones=[ctx.network().availability_zones[0]],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    policy_name = ctx.unique_name("sim2real-behav-predictive-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": 40,
                    "PredefinedMetricPairSpecification": {"PredefinedMetricType": "ASGCPUUtilization"},
                }
            ],
            "Mode": "ForecastOnly",
        },
    )
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)
        )
    )

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=1)
    end_time = now + timedelta(hours=6)

    try:
        forecast = asg.get_predictive_scaling_forecast(
            AutoScalingGroupName=group_name,
            PolicyName=policy_name,
            StartTime=start_time,
            EndTime=end_time,
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        raise AssertionError(
            f"GetPredictiveScalingForecast rejected the freshly-created policy with {code!r} "
            "(no forecast data available yet -- predictive scaling needs >=24h of history)"
        )

    assert "LoadForecast" in forecast, "response missing LoadForecast"
    # One load forecast per MetricSpecification, each naming the policy's own metric spec.
    assert len(forecast["LoadForecast"]) == 1, (
        f"expected one LoadForecast entry for the policy's one MetricSpecification, got {forecast['LoadForecast']!r}"
    )
    spec = forecast["LoadForecast"][0].get("MetricSpecification", {})
    assert spec.get("TargetValue") == 40.0, f"LoadForecast MetricSpecification TargetValue {spec!r}"
    assert spec.get("PredefinedMetricPairSpecification", {}).get("PredefinedMetricType") == "ASGCPUUtilization", (
        f"LoadForecast MetricSpecification metric pair {spec!r}"
    )
    assert "CapacityForecast" in forecast, "response missing CapacityForecast"
    cap = forecast["CapacityForecast"]
    assert "Timestamps" in cap and "Values" in cap, "CapacityForecast missing Timestamps/Values"
    assert len(cap["Timestamps"]) == len(cap["Values"]), (
        "CapacityForecast Timestamps/Values length mismatch -- not a coherent server-built series"
    )
    _assert_sane_values(cap["Values"], "CapacityForecast")

    for lf in forecast["LoadForecast"]:
        assert "Timestamps" in lf and "Values" in lf, f"LoadForecast entry missing Timestamps/Values: {lf!r}"
        assert len(lf["Timestamps"]) == len(lf["Values"]), (
            f"LoadForecast Timestamps/Values length mismatch: {len(lf['Timestamps'])} vs {len(lf['Values'])}"
        )
        _assert_sane_values(lf["Values"], "LoadForecast")

    # If the server did produce timestamped datapoints, they must be plausible hourly forecast
    # buckets within/near our requested window -- not a verbatim echo of StartTime/EndTime.
    all_timestamps = list(cap["Timestamps"])
    for lf in forecast["LoadForecast"]:
        all_timestamps.extend(lf["Timestamps"])
    if all_timestamps:
        assert all(t != start_time and t != end_time for t in all_timestamps), (
            "forecast timestamps are literal echoes of the request StartTime/EndTime"
        )
    # StartTime is inclusive and EndTime exclusive: every datapoint lies inside the window.
    outside = [t for t in all_timestamps if not start_time <= t < end_time]
    assert not outside, f"forecast timestamps outside [{start_time}, {end_time}): {outside[:5]}"




def _assert_sane_values(values, label: str) -> None:
    for v in values:
        assert isinstance(v, (int, float)), f"{label} value {v!r} is not a real number"
        assert math.isnan(v) or v >= 0, (
            f"{label} fabricated a nonsensical negative value: {v!r} "
            "(server may report NaN when it has no history, but never a negative load/capacity)"
        )


def _unless_gone(fn, *not_found):
    """Run one cleanup call; only a not-found answer means the resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in not_found or (
                err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            return
        raise


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(20):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise


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
