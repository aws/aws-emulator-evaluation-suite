"""put-scaling-policy-invalid-adjustment-type-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "put-scaling-policy-invalid-adjustment-type-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy must reject an unknown AdjustmentType rather than storing it."""
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
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
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
            "Tags": [
                {"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False}
            ],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    policy_name = ctx.unique_name("sim2real-behav-as-pol-")

    # Break exactly one thing: an AdjustmentType value outside the modelled enum.
    try:
        result = as_.put_scaling_policy(
            AutoScalingGroupName=name,
            PolicyName=policy_name,
            PolicyType="SimpleScaling",
            AdjustmentType="NotARealAdjustmentType",
            ScalingAdjustment=1,
        )
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Valid adjustment types are: [PercentChangeInCapacity, ChangeInCapacity, ExactCapacity]."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    resp = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])
    assert resp["ScalingPolicies"] == [], "rejected policy must not be persisted"

    # Positive control: the identical call with a real AdjustmentType is accepted and
    # persisted, so the rejection above is provably specific to the bad enum value and
    # not evidence that this account/target rejects every PutScalingPolicy call.
    good_policy_name = ctx.unique_name("sim2real-behav-as-pol-good-")
    good_resp = as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=good_policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
    )
    ctx.on_cleanup(
        lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=good_policy_name)
    )
    assert good_resp["PolicyARN"], "valid AdjustmentType must be accepted and return a PolicyARN"

    good_listed = as_.describe_policies(
        AutoScalingGroupName=name, PolicyNames=[good_policy_name]
    )["ScalingPolicies"]
    assert len(good_listed) == 1 and good_listed[0]["AdjustmentType"] == "ChangeInCapacity", (
        f"expected the valid policy to be persisted with its AdjustmentType, got {good_listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
