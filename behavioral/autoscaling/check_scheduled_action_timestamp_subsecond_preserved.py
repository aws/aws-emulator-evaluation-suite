"""scheduled-action-timestamp-subsecond-preserved."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "scheduled-action-timestamp-subsecond-preserved"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Scheduled-action StartTime/EndTime are stored at whole-second granularity: sub-second input
    to PutScheduledUpdateGroupAction is truncated (not preserved, not rounded up) on describe."""
    autoscaling = ctx.client("autoscaling")
    asg_name = _create_asg(ctx)
    action_name = ctx.unique_name("sim2real-behav-sched-")

    start = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    ).replace(microsecond=123456)
    end = (start + datetime.timedelta(days=400)).replace(microsecond=654321)

    autoscaling.put_scheduled_update_group_action(
        AutoScalingGroupName=asg_name,
        ScheduledActionName=action_name,
        StartTime=start,
        EndTime=end,
        Recurrence="0 0 1 1 *",
        DesiredCapacity=1,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_scheduled_action(
            AutoScalingGroupName=asg_name, ScheduledActionName=action_name
        )
    )

    resp = autoscaling.describe_scheduled_actions(
        AutoScalingGroupName=asg_name, ScheduledActionNames=[action_name]
    )
    actions = resp["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, f"expected exactly one scheduled action, got {actions!r}"
    got_start = actions[0]["StartTime"]
    got_end = actions[0]["EndTime"]

    # AWS truncates to whole seconds: it neither preserves microseconds nor rounds up.
    assert got_start.microsecond == 0, (
        f"StartTime sub-second component was not truncated to zero: got {got_start!r}"
    )
    assert got_end.microsecond == 0, (
        f"EndTime sub-second component was not truncated to zero: got {got_end!r}"
    )
    start_floor = start.replace(microsecond=0)
    end_floor = end.replace(microsecond=0)
    assert got_start == start_floor, (
        f"StartTime did not truncate (floor) to the submitted second: "
        f"sent {start!r} (floor {start_floor!r}), got {got_start!r}"
    )
    assert got_end == end_floor, (
        f"EndTime did not truncate (floor) to the submitted second: "
        f"sent {end!r} (floor {end_floor!r}), got {got_end!r}"
    )


def _create_launch_template(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": name}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_asg(ctx, *, min_size=0, max_size=1, desired=0):
    autoscaling = ctx.client("autoscaling")
    lt_id = _create_launch_template(ctx)
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real",
                "Value": asg_name,
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


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
