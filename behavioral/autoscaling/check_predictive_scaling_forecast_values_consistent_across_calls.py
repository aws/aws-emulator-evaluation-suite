"""predictive-scaling-forecast-values-consistent-across-calls."""
from __future__ import annotations

import datetime as dt
import math

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-values-consistent-across-calls"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two GetPredictiveScalingForecast calls for the same policy and window return identical
    LoadForecast and CapacityForecast: the forecast is a stable record, not regenerated per read.
    The policy is ForecastOnly so no capacity is launched."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet_id = _get_subnet_id(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": lt_name}]}
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
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": asg_name, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    policy_name = ctx.unique_name("sim2real-behav-predictive-")
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
        lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name)
    )

    now = dt.datetime.now(dt.timezone.utc)
    start_time = now - dt.timedelta(hours=1)
    end_time = now + dt.timedelta(hours=1)

    first = autoscaling.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        StartTime=start_time,
        EndTime=end_time,
    )
    second = autoscaling.get_predictive_scaling_forecast(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        StartTime=start_time,
        EndTime=end_time,
    )

    assert _forecast_series_equal(first["LoadForecast"], second["LoadForecast"]), (
        f"LoadForecast changed between calls: first={first['LoadForecast']!r} "
        f"second={second['LoadForecast']!r}"
    )
    assert _capacity_forecast_equal(first["CapacityForecast"], second["CapacityForecast"]), (
        f"CapacityForecast changed between calls: first={first['CapacityForecast']!r} "
        f"second={second['CapacityForecast']!r}"
    )
    # The response has no UpdateTime field, only LoadForecast and CapacityForecast.



def _values_equal(a, b) -> bool:
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    return a == b


def _forecast_series_equal(first, second) -> bool:
    """Compare a list of LoadForecast entries, treating NaN datapoints (returned
    by AWS when there is no CloudWatch history to forecast from) as equal to
    each other rather than using strict float `==` semantics."""
    if len(first) != len(second):
        return False
    for f_entry, s_entry in zip(first, second):
        if f_entry.get("Timestamps") != s_entry.get("Timestamps"):
            return False
        if f_entry.get("MetricSpecification") != s_entry.get("MetricSpecification"):
            return False
        f_values = f_entry.get("Values", [])
        s_values = s_entry.get("Values", [])
        if len(f_values) != len(s_values):
            return False
        if not all(_values_equal(a, b) for a, b in zip(f_values, s_values)):
            return False
    return True


def _capacity_forecast_equal(first, second) -> bool:
    """CapacityForecast is a single {Timestamps, Values} object (not a list),
    unlike LoadForecast -- compare it the same NaN-tolerant way."""
    if first.get("Timestamps") != second.get("Timestamps"):
        return False
    f_values = first.get("Values", [])
    s_values = second.get("Values", [])
    if len(f_values) != len(s_values):
        return False
    return all(_values_equal(a, b) for a, b in zip(f_values, s_values))

def _get_subnet_id(ec2, *, ctx) -> str:
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
