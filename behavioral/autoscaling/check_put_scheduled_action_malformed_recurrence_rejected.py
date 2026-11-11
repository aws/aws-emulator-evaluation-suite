"""put-scheduled-action-malformed-recurrence-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scheduled-action-malformed-recurrence-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScheduledUpdateGroupAction rejects a Recurrence string that is not a valid
    5-field cron expression instead of accepting an unparseable schedule and storing
    it as if it would eventually fire."""
    asgc = ctx.client("autoscaling")

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    lt_id = _create_launch_template(ctx)
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    malformed_action = ctx.unique_name("sim2real-behav-malformed-sched-")
    code, message = _error(
        lambda: asgc.put_scheduled_update_group_action(
            AutoScalingGroupName=asg_name,
            ScheduledActionName=malformed_action,
            Recurrence="not a cron expression",
            DesiredCapacity=1,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Given recurrence string: not a cron expression is invalid"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: the malformed scheduled action was never stored.
    actions = asgc.describe_scheduled_actions(
        AutoScalingGroupName=asg_name, ScheduledActionNames=[malformed_action]
    )["ScheduledUpdateGroupActions"]
    assert actions == [], f"malformed scheduled action should not exist, found: {actions}"

    # (c) positive control: the same call shape, with a valid cron recurrence, succeeds.
    valid_action = ctx.unique_name("sim2real-behav-valid-sched-")
    asgc.put_scheduled_update_group_action(
        AutoScalingGroupName=asg_name,
        ScheduledActionName=valid_action,
        Recurrence="30 0 1 1,6,12 *",
        DesiredCapacity=1,
    )
    ctx.on_cleanup(
        lambda: asgc.delete_scheduled_action(AutoScalingGroupName=asg_name, ScheduledActionName=valid_action)
    )
    actions = asgc.describe_scheduled_actions(
        AutoScalingGroupName=asg_name, ScheduledActionNames=[valid_action]
    )["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, "positive control scheduled action was not stored"


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return zones[0]["ZoneName"]


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
