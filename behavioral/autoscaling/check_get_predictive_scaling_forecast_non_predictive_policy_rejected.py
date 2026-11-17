"""get-predictive-scaling-forecast-non-predictive-policy-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-predictive-scaling-forecast-non-predictive-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPredictiveScalingForecast rejects a PolicyName that names a real, existing scaling
    policy of a type other than PredictiveScaling, while the same call against a real
    predictive scaling policy on that group succeeds."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    step_policy_name = ctx.unique_name("sim2real-behav-step-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=step_policy_name,
        PolicyType="StepScaling",
        AdjustmentType="ChangeInCapacity",
        StepAdjustments=[{"MetricIntervalLowerBound": 0.0, "ScalingAdjustment": 1}],
    )
    ctx.on_cleanup(lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=step_policy_name))

    now = datetime.now(timezone.utc)
    start, end = now, now + timedelta(days=1)

    code, message = _error(
        lambda: asg.get_predictive_scaling_forecast(
            AutoScalingGroupName=group_name, PolicyName=step_policy_name, StartTime=start, EndTime=end
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"Policy {step_policy_name} is not a predictive scaling policy."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    predictive_policy_name = ctx.unique_name("sim2real-behav-pred-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=predictive_policy_name,
        PolicyType="PredictiveScaling",
        PredictiveScalingConfiguration={
            "MetricSpecifications": [
                {"TargetValue": 70.0, "PredefinedMetricPairSpecification": {"PredefinedMetricType": "ASGCPUUtilization"}}
            ],
            "Mode": "ForecastOnly",
        },
    )
    ctx.on_cleanup(lambda: asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=predictive_policy_name))

    forecast = asg.get_predictive_scaling_forecast(
        AutoScalingGroupName=group_name, PolicyName=predictive_policy_name, StartTime=start, EndTime=end
    )
    assert "LoadForecast" in forecast, f"expected a LoadForecast key for a real predictive policy, got {forecast!r}"
    assert "CapacityForecast" in forecast, f"expected a CapacityForecast key for a real predictive policy, got {forecast!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
