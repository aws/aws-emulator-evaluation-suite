"""delete-policy-nonexistent-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-policy-nonexistent-noop"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy for a policy name that does not exist on the group fails with
    ValidationError, and DescribePolicies confirms no state change."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)

    real_policy_name = ctx.unique_name("sim2real-policy-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group_name,
        PolicyName=real_policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=60,
    )
    ctx.on_cleanup(lambda: _delete_policy_if_present(asg, group_name, real_policy_name))

    ghost_policy_name = ctx.unique_name("sim2real-policy-ghost-")
    before = {
        p["PolicyName"]
        for p in asg.describe_policies(AutoScalingGroupName=group_name)["ScalingPolicies"]
    }
    assert before == {real_policy_name}

    # Must raise ValidationError, and must not touch the unrelated real policy.
    from botocore.exceptions import ClientError

    try:
        asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=ghost_policy_name)
        raise AssertionError("expected DeletePolicy on a nonexistent policy to raise ValidationError")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationError", f"expected ValidationError, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == f"Policy {ghost_policy_name} not found", (
            f"expected message 'Policy {ghost_policy_name} not found', got {message!r}"
        )

    after = {
        p["PolicyName"]
        for p in asg.describe_policies(AutoScalingGroupName=group_name)["ScalingPolicies"]
    }
    assert after == {real_policy_name}, (
        f"a failed delete of a nonexistent policy must not change existing policy state, got {after}"
    )

    # Positive control: DeletePolicy against a policy that actually exists must succeed,
    # so the ValidationError above is proven specific to the nonexistent name rather than
    # a target that rejects every DeletePolicy call.
    asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=real_policy_name)
    gone = {
        p["PolicyName"]
        for p in asg.describe_policies(AutoScalingGroupName=group_name)["ScalingPolicies"]
    }
    assert gone == set(), f"a successful DeletePolicy must remove the policy, got {gone}"

    # The now-deleted real policy is itself a nonexistent name: a repeat delete must fail
    # with the same ValidationError, not silently succeed a second time.
    try:
        asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=real_policy_name)
        raise AssertionError("expected DeletePolicy on an already-deleted policy to raise ValidationError")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationError", f"expected ValidationError on repeat delete, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == f"Policy {real_policy_name} not found", (
            f"expected message 'Policy {real_policy_name} not found', got {message!r}"
        )


def _delete_policy_if_present(asg, group_name: str, policy_name: str) -> None:
    present = asg.describe_policies(AutoScalingGroupName=group_name, PolicyNames=[policy_name])["ScalingPolicies"]
    if present:
        asg.delete_policy(AutoScalingGroupName=group_name, PolicyName=policy_name)


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    # NOTE: real AWS now rejects CreateLaunchConfiguration for many accounts
    # ("Launch Configuration creation operation is not available"), so use a
    # launch template instead -- equivalent for exercising the ASG behavior
    # under test here.
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
    group_name = ctx.unique_name("sim2real-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))
    return group_name


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
