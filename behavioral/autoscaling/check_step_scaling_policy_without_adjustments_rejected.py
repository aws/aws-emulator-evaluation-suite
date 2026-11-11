"""step-scaling-policy-without-adjustments-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "step-scaling-policy-without-adjustments-rejected"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A StepScaling policy with no StepAdjustments is rejected; the identical call with
    StepAdjustments succeeds, so the rejection is due to the missing adjustments."""
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
        raise AssertionError(
            f"expected this PutScalingPolicy to be rejected, but it SUCCEEDED and returned "
            f"{result!r}"
        )

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)

    # Positive control: the identical call shape, with StepAdjustments supplied, succeeds --
    # without this, "rejects a StepScaling policy with no adjustments" is indistinguishable
    # from "rejects every StepScaling PutScalingPolicy".
    good_policy = ctx.unique_name("sim2real-behav-as-step-good-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=good_policy,
        PolicyType="StepScaling",
        AdjustmentType="ChangeInCapacity",
        StepAdjustments=[{"MetricIntervalLowerBound": 0.0, "ScalingAdjustment": 1}],
    )
    ctx.on_cleanup(
        lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=good_policy)
    )
    good = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[good_policy])[
        "ScalingPolicies"
    ]
    assert len(good) == 1, (
        f"the positive control (StepAdjustments supplied) did not register: {good!r}"
    )

    bad_policy = ctx.unique_name("sim2real-behav-as-step-bad-")
    code, message = _error(
        lambda: as_.put_scaling_policy(
            AutoScalingGroupName=name,
            PolicyName=bad_policy,
            PolicyType="StepScaling",
            AdjustmentType="ChangeInCapacity",
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = "You should specify at least one StepAdjustment with a StepScaling policy."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    bad = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[bad_policy])[
        "ScalingPolicies"
    ]
    assert bad == [], f"no policy may be created from a rejected PutScalingPolicy: {bad!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
