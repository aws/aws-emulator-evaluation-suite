"""rollback-instance-refresh-no-active-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rollback-instance-refresh-no-active-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackInstanceRefresh on a never-refreshed group pinned to launch template '$Latest' fails
    with IrreversibleInstanceRefresh citing the template version, not a missing active refresh."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)

    code, message = _error(lambda: asg.rollback_instance_refresh(AutoScalingGroupName=group_name))
    assert code == "IrreversibleInstanceRefresh", f"expected IrreversibleInstanceRefresh, got {code}"
    expected_message = (
        "This Auto Scaling group's launch template version isn't compatible with a rollback. "
        "Rollbacks are not supported when the Auto Scaling group uses the launch template's "
        "'$Latest' or '$Default' version."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # DescribeInstanceRefreshes should confirm there is nothing to roll back.
    refreshes = asg.describe_instance_refreshes(AutoScalingGroupName=group_name)["InstanceRefreshes"]
    assert refreshes == [], f"expected no instance refreshes to exist, found {refreshes}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). Raises on unexpected success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    # Many accounts cannot call CreateLaunchConfiguration ("Launch Configuration creation
    # operation is not available"), so use a launch template.
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
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
