"""predictive-scaling-forecast-reflects-updated-policy."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-reflects-updated-policy"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An updated predictive scaling policy's new TargetValue and metric type are what
    DescribePolicies returns, and GetPredictiveScalingForecast keeps serving a well-formed forecast.
    """
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

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
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    policy_name = ctx.unique_name("sim2real-behav-predictive-")
    initial_target = 40.0
    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": initial_target,
                    "PredefinedMetricPairSpecification": {
                        "PredefinedMetricType": "ASGCPUUtilization"
                    },
                }
            ],
            "Mode": "ForecastOnly",
        },
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name)
    )

    now = dt.datetime.now(dt.timezone.utc)
    start_time = now - dt.timedelta(hours=1)
    end_time = now + dt.timedelta(hours=1)

    baseline = autoscaling.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        StartTime=start_time,
        EndTime=end_time,
    )
    assert "LoadForecast" in baseline and "CapacityForecast" in baseline, (
        f"baseline forecast missing LoadForecast/CapacityForecast: {baseline}"
    )

    described = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert len(described) == 1, f"expected exactly 1 policy named {policy_name}, got {described}"
    initial_spec = described[0]["PredictiveScalingConfiguration"]["MetricSpecifications"][0]
    assert initial_spec["TargetValue"] == initial_target, (
        f"expected initial TargetValue {initial_target}, got {initial_spec['TargetValue']}"
    )
    assert (
        initial_spec["PredefinedMetricPairSpecification"]["PredefinedMetricType"]
        == "ASGCPUUtilization"
    ), f"expected initial PredefinedMetricType ASGCPUUtilization, got {initial_spec}"

    updated_target = 65.0
    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {
                    "TargetValue": updated_target,
                    "PredefinedMetricPairSpecification": {
                        "PredefinedMetricType": "ASGNetworkIn"
                    },
                }
            ],
            "Mode": "ForecastOnly",
        },
    )

    described = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert len(described) == 1, f"expected exactly 1 policy named {policy_name}, got {described}"
    updated_spec = described[0]["PredictiveScalingConfiguration"]["MetricSpecifications"][0]
    assert updated_spec["TargetValue"] == updated_target, (
        f"PutScalingPolicy update did not persist the new TargetValue: "
        f"expected {updated_target}, got {updated_spec['TargetValue']}"
    )
    assert (
        updated_spec["PredefinedMetricPairSpecification"]["PredefinedMetricType"]
        == "ASGNetworkIn"
    ), (
        f"PutScalingPolicy update did not persist the new predefined metric type: "
        f"expected ASGNetworkIn, got {updated_spec['PredefinedMetricPairSpecification']}"
    )
    assert updated_spec["TargetValue"] != initial_target, (
        f"updated TargetValue {updated_spec['TargetValue']} should differ from initial {initial_target}"
    )

    # Only shape is asserted: forecasts need >= 24h of load history, so a new group's forecast is
    # empty before and after the update.
    after_update = autoscaling.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        StartTime=start_time,
        EndTime=end_time,
    )
    assert "LoadForecast" in after_update and "CapacityForecast" in after_update, (
        f"post-update forecast missing LoadForecast/CapacityForecast: {after_update}"
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
