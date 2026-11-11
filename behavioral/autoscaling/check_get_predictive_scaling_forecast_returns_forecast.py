"""get-predictive-scaling-forecast-returns-forecast."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-predictive-scaling-forecast-returns-forecast"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy with PolicyType=PredictiveScaling creates a policy backed by a
    server-computed forecast, and GetPredictiveScalingForecast returns that forecast
    as parallel Timestamps/Values series for both the load and capacity forecasts."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    asg_name = _create_empty_asg(ctx)

    policy_name = ctx.unique_name("sim2real-behav-predpolicy-")
    metric_specs = [
        {
            "TargetValue": 40.0,
            "PredefinedMetricPairSpecification": {
                "PredefinedMetricType": "ASGCPUUtilization",
            },
        }
    ]
    put_resp = autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": metric_specs,
            "Mode": "ForecastOnly",
            "MaxCapacityBreachBehavior": "HonorMaxCapacity",
        },
    )
    ctx.on_cleanup(lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name))
    assert put_resp["PolicyARN"].endswith(policy_name), (
        f"expected PolicyARN to end with {policy_name!r}, got {put_resp['PolicyARN']!r}"
    )

    now = datetime.now(timezone.utc)
    try:
        forecast = autoscaling.get_predictive_scaling_forecast(
            AutoScalingGroupName=asg_name,
            PolicyName=policy_name,
            StartTime=now,
            EndTime=now + timedelta(hours=24),
        )
    except ClientError as exc:
        raise AssertionError(f"forecast unavailable: {exc.response['Error']}") from exc

    load_forecasts = forecast.get("LoadForecast")
    assert isinstance(load_forecasts, list), f"expected LoadForecast to be a list, got {load_forecasts!r}"
    # Real AWS always returns one LoadForecast entry per configured metric specification, even
    # immediately after policy creation before enough CloudWatch history exists for numeric data
    # points -- only the per-entry Timestamps/Values arrays inside may be empty, never the entry
    # list itself. A target that answers with an empty LoadForecast list has no forecast at all.
    assert len(load_forecasts) == len(metric_specs), (
        f"expected one LoadForecast entry per configured metric specification "
        f"({len(metric_specs)}), got {len(load_forecasts)}: {load_forecasts}"
    )
    assert "CapacityForecast" in forecast, f"response missing CapacityForecast: {forecast}"
    # UpdateTime reflects when the server last computed the forecast; for a policy that was
    # just created, the server may not have run a forecast computation yet, so this field can
    # be legitimately absent immediately after PutScalingPolicy. Only validate its type when
    # present rather than requiring it (LoadForecast/CapacityForecast are the guaranteed fields).
    if "UpdateTime" in forecast:
        assert isinstance(forecast["UpdateTime"], datetime), (
            f"expected UpdateTime to be a datetime, got {type(forecast['UpdateTime'])!r}"
        )

    for load in load_forecasts:
        assert "Timestamps" in load and "Values" in load, f"malformed LoadForecast entry: {load}"
        assert len(load["Timestamps"]) == len(load["Values"]), (
            f"Timestamps/Values length mismatch in LoadForecast entry: {load}"
        )
        assert "MetricSpecification" in load, f"LoadForecast entry missing MetricSpecification: {load}"
        pair = load["MetricSpecification"].get("PredefinedMetricPairSpecification", {})
        if pair:
            assert pair["PredefinedMetricType"] == "ASGCPUUtilization", (
                f"expected PredefinedMetricType ASGCPUUtilization, got {pair['PredefinedMetricType']!r}"
            )

    capacity = forecast["CapacityForecast"]
    assert "Timestamps" in capacity and "Values" in capacity, f"malformed CapacityForecast: {capacity}"
    assert len(capacity["Timestamps"]) == len(capacity["Values"]), (
        f"Timestamps/Values length mismatch in CapacityForecast: {capacity}"
    )


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")
    return param["Parameter"]["Value"]


def _get_subnet_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _create_empty_asg(ctx) -> str:
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_al2_ami(ctx)
    subnet_id = _get_subnet_id(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    _wait_for_group_status_settled(ctx, asg_name)
    return asg_name


def _wait_for_group_status_settled(ctx, asg_name: str, timeout_s: float = 60.0) -> None:
    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = described["AutoScalingGroups"]
        if groups and groups[0].get("AutoScalingGroupName") == asg_name:
            return
        time.sleep(2)
    raise AssertionError(f"group {asg_name} never became describable")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
