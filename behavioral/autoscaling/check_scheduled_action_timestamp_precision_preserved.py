"""scheduled-action-timestamp-precision-preserved."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "scheduled-action-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartTime/EndTime timestamps set on a scheduled action are returned by
    DescribeScheduledActions with full precision and no timezone/format drift --
    the returned datetimes must compare exactly equal to what was submitted."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2, ctx=ctx)
    ami_id = _latest_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start_time = now + dt.timedelta(hours=2, seconds=17)
    end_time = now + dt.timedelta(hours=3, seconds=43)

    action_name = ctx.unique_name("sim2real-behav-schedule-")
    autoscaling.put_scheduled_update_group_action(
        AutoScalingGroupName=asg_name,
        ScheduledActionName=action_name,
        StartTime=start_time,
        EndTime=end_time,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_scheduled_action(
            AutoScalingGroupName=asg_name, ScheduledActionName=action_name
        )
    )

    actions = autoscaling.describe_scheduled_actions(
        AutoScalingGroupName=asg_name, ScheduledActionNames=[action_name]
    )["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, (
        f"expected exactly one scheduled action named {action_name!r}, got {actions!r}"
    )
    returned = actions[0]
    assert returned["StartTime"] == start_time, (
        f"StartTime drifted: sent {start_time!r}, got {returned['StartTime']!r}"
    )
    assert returned["EndTime"] == end_time, (
        f"EndTime drifted: sent {end_time!r}, got {returned['EndTime']!r}"
    )


def _first_available_az(ec2, *, ctx) -> str:
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    return zones[0]["ZoneName"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


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
