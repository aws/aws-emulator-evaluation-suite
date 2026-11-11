"""scaling-policy-delete-removes-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "scaling-policy-delete-removes-policy"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy removes the policy from DescribePolicies results."""
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

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    policy_name = ctx.unique_name("sim2real-behav-as-pol-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
    )

    resp = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])
    assert len(resp["ScalingPolicies"]) == 1, (
        f"expected exactly one policy named {policy_name}, got {resp['ScalingPolicies']}"
    )

    as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name)

    resp = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])
    assert resp["ScalingPolicies"] == [], "deleted policy must no longer be listed"

    # A deleted policy is not just absent from the list, it is unusable: a second
    # delete against the now-dead name must be rejected, not silently accepted.
    try:
        as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name)
        raise AssertionError(
            "expected DeletePolicy on the already-deleted policy name to raise ValidationError"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationError", f"expected ValidationError, got {code}"
        expected_message = f"Policy {policy_name} not found"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    resp = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])
    assert resp["ScalingPolicies"] == [], "the rejected repeat delete must not resurrect the policy"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
