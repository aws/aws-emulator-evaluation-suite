"""metrics-collection-enable-disable."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "metrics-collection-enable-disable"
GROUP = 'metrics'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableMetricsCollection registers named metrics; Disable removes named ones (or all when omitted)."""
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

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
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
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
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
        raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

    name = _make_asg(min_size=0, max_size=1, desired_capacity=0)
    baseline = _describe_group(name).get("EnabledMetrics", [])
    assert baseline == [], f"expected no metrics enabled on a fresh ASG, got {baseline}"

    as_.enable_metrics_collection(
        AutoScalingGroupName=name,
        Granularity="1Minute",
        Metrics=["GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity"],
    )
    enabled = {m["Metric"]: m["Granularity"] for m in _describe_group(name)["EnabledMetrics"]}
    assert set(enabled) == {"GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity"}, enabled
    assert set(enabled.values()) == {"1Minute"}, enabled

    as_.disable_metrics_collection(AutoScalingGroupName=name, Metrics=["GroupMinSize"])
    enabled2 = {m["Metric"] for m in _describe_group(name)["EnabledMetrics"]}
    assert enabled2 == {"GroupMaxSize", "GroupDesiredCapacity"}, enabled2

    # Omitting Metrics disables every metric.
    as_.disable_metrics_collection(AutoScalingGroupName=name)
    after_disable_all = _describe_group(name).get("EnabledMetrics", [])
    assert after_disable_all == [], (
        f"omitting Metrics on DisableMetricsCollection must disable everything, got {after_disable_all}"
    )

    code, message = _error(
        lambda: as_.enable_metrics_collection(
            AutoScalingGroupName=name, Granularity="5Minute", Metrics=["GroupMinSize"]
        )
    )
    assert code == "ValidationError", (
        f"an unsupported granularity must be rejected, got {code}"
    )
    expected = "Valid metrics granularity type is: [1Minute]."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after_rejected = _describe_group(name).get("EnabledMetrics", [])
    assert after_rejected == [], (
        f"a rejected EnableMetricsCollection must not enable anything, got {after_rejected}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
