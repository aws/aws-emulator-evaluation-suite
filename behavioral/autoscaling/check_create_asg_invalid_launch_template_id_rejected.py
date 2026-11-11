"""create-asg-invalid-launch-template-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asg-invalid-launch-template-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with a nonexistent LaunchTemplateId fails with ValidationError
    "Malformed launch template Id" and creates no group; a real LaunchTemplateId succeeds."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _get_amazon_linux_ami(ctx)
    az = _get_az(ctx)

    bogus_lt_id = "lt-00000000000000000"  # well-formed, but does not exist
    asg_name = ctx.unique_name("sim2real-behav-asg-")

    code, message = _error_code(
        lambda: autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": bogus_lt_id, "Version": "$Latest"},
            MinSize=0,
            MaxSize=1,
            AvailabilityZones=[az],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == f"Malformed launch template Id: {bogus_lt_id}", (
        f"expected the exact nonexistent-LaunchTemplateId refusal message, got {message!r}"
    )

    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert groups == [], "ASG should not exist after the invalid-LaunchTemplateId create was rejected"

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    lt_id = lt_resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1 and groups[0]["AutoScalingGroupName"] == asg_name, (
        f"expected exactly one ASG named {asg_name!r} after the valid-LaunchTemplate create, "
        f"got {groups!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
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

