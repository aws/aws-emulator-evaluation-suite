"""predictive-scaling-policy-and-forecast."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "predictive-scaling-policy-and-forecast"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PredictiveScaling policy is stored verbatim and its forecast is queryable; unknown policies are rejected."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {
                    "ResourceType": "launch-template",
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                }
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )

    name = _make_asg(min_size=0, max_size=4, desired_capacity=0)
    policy_name = ctx.unique_name("sim2real-behav-as-ps-")

    as_.put_scaling_policy(
        AutoScalingGroupName=name,
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
    ctx.on_cleanup(lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name))

    policy = as_.describe_policies(
        AutoScalingGroupName=name, PolicyNames=[policy_name]
    )["ScalingPolicies"][0]
    assert policy["PolicyType"] == "PredictiveScaling", policy
    config = policy["PredictiveScalingConfiguration"]
    assert config["Mode"] == "ForecastOnly", config
    assert config["MetricSpecifications"][0]["TargetValue"] == 50.0, config

    start = datetime.now(timezone.utc)
    forecast = as_.get_predictive_scaling_forecast(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        StartTime=start,
        EndTime=start + timedelta(hours=6),
    )
    load_forecast = forecast.get("LoadForecast")
    assert isinstance(load_forecast, list), forecast
    for load in load_forecast:
        assert len(load["Timestamps"]) == len(load["Values"]), load
    capacity_forecast = forecast.get("CapacityForecast")
    assert isinstance(capacity_forecast, dict), forecast
    assert len(capacity_forecast["Timestamps"]) == len(capacity_forecast["Values"]), (
        capacity_forecast
    )

    missing_policy = ctx.unique_name("sim2real-behav-as-nopol-")
    code, message = _error(
        lambda: as_.get_predictive_scaling_forecast(
            AutoScalingGroupName=name,
            PolicyName=missing_policy,
            StartTime=start,
            EndTime=start + timedelta(hours=6),
        )
    )
    assert code == "ValidationError", (
        f"forecast for an unknown policy: expected ValidationError, got {code}"
    )
    expected = f"Policy {missing_policy} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
