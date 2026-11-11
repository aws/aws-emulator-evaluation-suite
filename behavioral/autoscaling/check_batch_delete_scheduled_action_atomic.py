"""batch-delete-scheduled-action-atomic."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "batch-delete-scheduled-action-atomic"
GROUP = "ordering"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteScheduledAction given only existing names deletes all of them in one call with no
    FailedScheduledActions, and none remain in DescribeScheduledActions afterward."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=3, desired=0)

    now = dt.datetime.now(dt.timezone.utc)
    names = [ctx.unique_name(f"sim2real-sched-{i}-") for i in range(3)]
    actions = [
        {
            "ScheduledActionName": n,
            "StartTime": now + dt.timedelta(days=10 + i),
            "MinSize": 0,
            "MaxSize": 3,
            "DesiredCapacity": 1,
        }
        for i, n in enumerate(names)
    ]
    put_resp = asg.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=group_name, ScheduledUpdateGroupActions=actions
    )
    assert not put_resp.get("FailedScheduledUpdateGroupActions"), put_resp.get("FailedScheduledUpdateGroupActions")

    before = asg.describe_scheduled_actions(AutoScalingGroupName=group_name, ScheduledActionNames=names)
    assert len(before["ScheduledUpdateGroupActions"]) == 3, (
        f"expected all 3 actions to exist before deletion, got {before['ScheduledUpdateGroupActions']}"
    )

    delete_resp = asg.batch_delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionNames=names)
    assert not delete_resp.get("FailedScheduledActions"), (
        f"batch delete reported partial failures: {delete_resp.get('FailedScheduledActions')}"
    )

    after = asg.describe_scheduled_actions(AutoScalingGroupName=group_name, ScheduledActionNames=names)
    remaining = after["ScheduledUpdateGroupActions"]
    assert remaining == [], f"expected no leftover scheduled actions after atomic batch delete, found {remaining}"


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
