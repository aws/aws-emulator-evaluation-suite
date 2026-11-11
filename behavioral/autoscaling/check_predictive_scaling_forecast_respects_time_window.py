"""predictive-scaling-forecast-respects-time-window."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-respects-time-window"
GROUP = "data-plane"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPredictiveScalingForecast returns forecast timestamps inside the requested [StartTime, EndTime)
    window, moving with the window, with Values length-aligned to Timestamps."""
    asgc = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "behav"}]}
        ],
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
        Tags=[{"Key": "sim2real", "Value": "behav", "PropagateAtLaunch": False}],
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
    windows = [
        (now, now + timedelta(hours=24)),
        (now + timedelta(days=10), now + timedelta(days=11)),
    ]
    for start, end in windows:
        resp = asgc.get_predictive_scaling_forecast(
            AutoScalingGroupName=asg_name, PolicyName=policy_name, StartTime=start, EndTime=end
        )
        load_forecasts = resp["LoadForecast"]
        assert len(load_forecasts) == 1, f"expected exactly one load forecast (one metric spec), got {load_forecasts}"
        echoed_spec = load_forecasts[0]["MetricSpecification"]["PredefinedMetricPairSpecification"]
        assert echoed_spec["PredefinedMetricType"] == "ASGCPUUtilization"

        _assert_bounded(load_forecasts[0]["Timestamps"], load_forecasts[0]["Values"], start, end)
        capacity_forecast = resp["CapacityForecast"]
        _assert_bounded(capacity_forecast["Timestamps"], capacity_forecast["Values"], start, end)

        # UpdateTime is only populated once the service has actually computed a forecast for
        # this policy; a brand-new policy legitimately omits it, so only type-check when present.
        if "UpdateTime" in resp:
            assert isinstance(resp["UpdateTime"], datetime)

    # Overly-permissive check: GetPredictiveScalingForecast against a policy that exists but is
    # NOT a PredictiveScaling policy must be rejected outright, not silently answer with a
    # (fabricated) forecast for a policy that was never configured to produce one.
    simple_policy_name = ctx.unique_name("sim2real-behav-simplepolicy-")
    asgc.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=simple_policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=60,
    )
    ctx.on_cleanup(lambda: asgc.delete_policy(AutoScalingGroupName=asg_name, PolicyName=simple_policy_name))

    try:
        result = asgc.get_predictive_scaling_forecast(
            AutoScalingGroupName=asg_name,
            PolicyName=simple_policy_name,
            StartTime=now,
            EndTime=now + timedelta(hours=24),
        )
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected a forecast for a non-predictive policy to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    assert code == "ValidationError", (
        f"expected ValidationError requesting a forecast for a non-predictive policy, got {code}"
    )
    expected_message = f"Policy {simple_policy_name} is not a predictive scaling policy."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"



def _assert_bounded(timestamps, values, start, end) -> None:
    assert len(timestamps) == len(values), (
        f"Timestamps/Values length mismatch: {len(timestamps)} vs {len(values)}"
    )
    for ts in timestamps:
        assert start <= ts < end, f"forecast timestamp {ts} fell outside requested window [{start}, {end})"


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
