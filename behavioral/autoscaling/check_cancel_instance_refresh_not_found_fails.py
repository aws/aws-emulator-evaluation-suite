"""cancel-instance-refresh-not-found-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cancel-instance-refresh-not-found-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelInstanceRefresh with no active refresh fails with ActiveInstanceRefreshNotFound rather
    than succeeding as a no-op, while cancelling an active refresh on a twin group succeeds."""
    asg = ctx.client("autoscaling")

    control_group = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)
    refresh_id = asg.start_instance_refresh(AutoScalingGroupName=control_group)["InstanceRefreshId"]
    cancel_resp = asg.cancel_instance_refresh(AutoScalingGroupName=control_group)
    assert cancel_resp["InstanceRefreshId"] == refresh_id, (
        f"positive control: expected cancel to return the active refresh id {refresh_id!r}, "
        f"got {cancel_resp.get('InstanceRefreshId')!r}"
    )

    subject_group = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)
    code, message = _client_error(lambda: asg.cancel_instance_refresh(AutoScalingGroupName=subject_group))
    assert code == "ActiveInstanceRefreshNotFound", f"expected ActiveInstanceRefreshNotFound, got {code}"
    expected = (
        "No in progress, baking, pending, or cancelling Instance Refresh found for Auto Scaling "
        f"group {subject_group}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    refreshes = asg.describe_instance_refreshes(AutoScalingGroupName=subject_group)["InstanceRefreshes"]
    assert refreshes == [], f"expected no instance refreshes for {subject_group}, found {refreshes}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. Success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    # CreateLaunchConfiguration is unavailable to many accounts, so use a launch template.
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
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
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
