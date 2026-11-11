"""scheduled-action-time-window-triggers."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "scheduled-action-time-window-triggers"
GROUP = "visibility-timeout-ttl"
SERVICES = ["autoscaling"]


# timing:real-time — schedule: 25 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scheduled-scaling.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A scheduled action's start/end window governs its visibility: DescribeScheduledActions
    only returns actions that haven't run or haven't reached their end time yet."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=3, desired=0)

    now = dt.datetime.now(dt.timezone.utc)
    expired_name = ctx.unique_name("sim2real-sched-expired-")
    active_name = ctx.unique_name("sim2real-sched-active-")

    # NOTE ON REAL BEHAVIOR: PutScheduledUpdateGroupAction rejects a StartTime that is
    # already in the past ("Given start time is in the past"), so we cannot directly create
    # an already-elapsed window. Instead, schedule a window that starts and ends a few
    # seconds from now, then poll until it naturally drops out of DescribeScheduledActions.
    expire_start = now + dt.timedelta(seconds=15)
    expire_end = now + dt.timedelta(seconds=25)
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=expired_name,
        StartTime=expire_start,
        EndTime=expire_end,
        DesiredCapacity=0,
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=expired_name), "ValidationError", message="not found")
    )

    # A window that is entirely in the future.
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=active_name,
        StartTime=now + dt.timedelta(days=2),
        EndTime=now + dt.timedelta(days=3),
        DesiredCapacity=0,
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=active_name), "ValidationError", message="not found")
    )

    # Bounded poll: wait for DescribeScheduledActions to stop returning the short-lived action.
    names_present: set[str] = set()
    expired_gone = False
    disappeared_at: dt.datetime | None = None
    first_iteration = True
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while time.monotonic() < deadline:
        described = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
        names_present = {a["ScheduledActionName"] for a in described}
        if first_iteration:
            # Positive control, taken well before EndTime: a target with no delivery path
            # at all (never lists the action) must not be indistinguishable from one that
            # correctly withholds it only after expiry.
            assert expired_name in names_present, (
                "the not-yet-expired action should be visible in DescribeScheduledActions "
                f"immediately after creation, but it was not: {names_present}"
            )
            first_iteration = False
        if expired_name not in names_present:
            expired_gone = True
            disappeared_at = dt.datetime.now(dt.timezone.utc)
            break
        time.sleep(1)

    if not expired_gone and _budget_spent(ctx):
        raise TimeoutError("the expired scheduled action leaving DescribeScheduledActions: the run "
                           "budget ended first; not graded")
    assert expired_gone, (
        "an action whose EndTime has already passed should no longer be returned by "
        f"DescribeScheduledActions, but it was still present after the poll deadline: {names_present}"
    )
    # A one-time action stops being listed once it has run (at StartTime) or reached EndTime,
    # so the earliest it may vanish is StartTime.
    assert disappeared_at is not None and disappeared_at >= expire_start - dt.timedelta(seconds=2), (
        "the action disappeared from DescribeScheduledActions before its StartTime had actually "
        f"passed: observed gone at {disappeared_at}, but StartTime was {expire_start}"
    )
    assert active_name in names_present, "an action within its active window should be visible"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
