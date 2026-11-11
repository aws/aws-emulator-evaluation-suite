"""delete-scheduled-action-nonexistent-noop."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "delete-scheduled-action-nonexistent-noop"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteScheduledAction for a never-created name fails with ValidationError and leaves the
    group unchanged, while deleting a name that exists succeeds, so a blanket rejection cannot pass.
    """
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=1, desired=0)

    from botocore.exceptions import ClientError

    # Positive control: the same call shape, against a scheduled action that genuinely exists,
    # must succeed -- otherwise "rejects a ghost name" is indistinguishable from "rejects every
    # DeleteScheduledAction".
    control_name = ctx.unique_name("sim2real-sched-control-")
    start_time = datetime.now(timezone.utc) + timedelta(days=30)
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=control_name,
        StartTime=start_time,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
    )
    control_actions = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert any(a["ScheduledActionName"] == control_name for a in control_actions), (
        f"positive control action {control_name!r} not visible after PutScheduledUpdateGroupAction: "
        f"{control_actions}"
    )
    asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=control_name)
    control_after = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert not any(a["ScheduledActionName"] == control_name for a in control_after), (
        f"positive control action {control_name!r} still present after DeleteScheduledAction succeeded: "
        f"{control_after}"
    )

    never_created_name = ctx.unique_name("sim2real-sched-ghost-")

    before = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert before == [], f"group should have no scheduled actions after the positive control cleaned up its own, got {before}"

    try:
        asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=never_created_name)
        raise AssertionError("expected DeleteScheduledAction on a nonexistent action to raise ValidationError")
    except ClientError as exc:
        error = exc.response["Error"]
        code = error["Code"]
        assert code == "ValidationError", f"expected ValidationError, got {code}: {error.get('Message')!r}"
        message = error.get("Message", "")
        assert message == "Scheduled action name not found", (
            f"expected message 'Scheduled action name not found', got {message!r}"
        )

    after = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert after == [], f"a failed delete of a nonexistent scheduled action should not change group state, got {after}"

    # Restore leg: the rejected name is not wedged -- it can be created and deleted like any
    # other, proving the refusal was about the name never having existed, not about the name
    # itself being permanently unusable.
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=never_created_name,
        StartTime=start_time,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
    )
    reused_actions = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert any(a["ScheduledActionName"] == never_created_name for a in reused_actions), (
        f"the previously-rejected name {never_created_name!r} could not be created after the "
        f"failed delete: {reused_actions}"
    )
    asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=never_created_name)
    final_actions = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert not any(a["ScheduledActionName"] == never_created_name for a in final_actions), (
        f"the previously-rejected name {never_created_name!r} still present after its own real "
        f"delete: {final_actions}"
    )


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _create_shell_asg(ctx, min_size: int, max_size: int, desired: int) -> str:
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    # AWS rejects CreateLaunchConfiguration for many accounts, so use a launch template.
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
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
