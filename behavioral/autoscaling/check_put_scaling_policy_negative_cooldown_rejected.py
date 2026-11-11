"""put-scaling-policy-negative-cooldown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-negative-cooldown-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy with a negative Cooldown is rejected as out-of-range,
    distinct from the already-covered invalid-AdjustmentType rejection."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)
    az = _get_az(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[
            {
                "Key": "sim2real:managed",
                "Value": "true",
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )

    policy_name = ctx.unique_name("sim2real-behav-policy-")

    # Break exactly one thing: a negative Cooldown value.
    code, message = _error(
        lambda: autoscaling.put_scaling_policy(
            AutoScalingGroupName=asg_name,
            PolicyName=policy_name,
            PolicyType="SimpleScaling",
            AdjustmentType="ChangeInCapacity",
            ScalingAdjustment=1,
            Cooldown=-1,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '-1' at 'cooldown' failed to satisfy constraint: "
        "Member must have value greater than or equal to 0"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no policy was created.
    policies = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert policies == [], "policy should not exist after the negative-cooldown put was rejected"

    # Positive control: the same call succeeds with a valid (non-negative) cooldown.
    resp = autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=300,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name))
    assert resp["PolicyARN"], f"expected a PolicyARN in the response, got {resp!r}"
    policies = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name, PolicyNames=[policy_name]
    )["ScalingPolicies"]
    assert len(policies) == 1 and policies[0]["Cooldown"] == 300, (
        f"expected exactly one policy with Cooldown=300, got {policies!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_amazon_linux_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _get_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]


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
