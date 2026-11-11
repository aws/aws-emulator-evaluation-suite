"""batch-put-scheduled-actions-malformed-recurrence-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-put-scheduled-actions-malformed-recurrence-rejected"
GROUP = "negative-classes"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchPutScheduledUpdateGroupAction reports an item with an invalid cron recurrence in
    FailedScheduledUpdateGroupActions (ValidationError) and persists only the valid sibling."""
    asg = _create_empty_group(ctx)
    autoscaling = ctx.client("autoscaling")

    good_name = ctx.unique_name("sim2real-behav-sched-good-")
    bad_name = ctx.unique_name("sim2real-behav-sched-bad-")

    resp = autoscaling.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=asg,
        ScheduledUpdateGroupActions=[
            {
                "ScheduledActionName": good_name,
                "Recurrence": "0 10 * * *",
                "MinSize": 0,
                "MaxSize": 1,
                "DesiredCapacity": 1,
            },
            {
                "ScheduledActionName": bad_name,
                "Recurrence": "not a cron expression!!",
                "MinSize": 0,
                "MaxSize": 1,
                "DesiredCapacity": 1,
            },
        ],
    )
    ctx.on_cleanup(
        lambda: autoscaling.batch_delete_scheduled_action(
            AutoScalingGroupName=asg, ScheduledActionNames=[good_name]
        )
    )

    failed = {f["ScheduledActionName"]: f for f in resp["FailedScheduledUpdateGroupActions"]}
    assert bad_name in failed, (
        f"expected {bad_name!r} (malformed recurrence) in FailedScheduledUpdateGroupActions, "
        f"got: {resp['FailedScheduledUpdateGroupActions']!r}"
    )
    assert failed[bad_name]["ErrorCode"] == "ValidationError", (
        f"expected ErrorCode ValidationError for {bad_name!r}, got: {failed[bad_name]!r}"
    )
    assert failed[bad_name].get("ErrorMessage") == "Given recurrence string: not a cron expression!! is invalid", (
        f"expected the exact ErrorMessage for {bad_name!r}, got: {failed[bad_name]!r}"
    )
    assert good_name not in failed, (
        f"well-formed sibling {good_name!r} must not be reported as failed, got: {failed!r}"
    )

    listed = autoscaling.describe_scheduled_actions(
        AutoScalingGroupName=asg, ScheduledActionNames=[good_name, bad_name]
    )["ScheduledUpdateGroupActions"]
    names = {a["ScheduledActionName"] for a in listed}
    assert names == {good_name}, (
        f"expected only the well-formed sibling {good_name!r} to be persisted, found: {names!r}"
    )


def _create_empty_group(ctx) -> str:
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
    )
    lt_id = lt["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real:managed",
                "Value": "true",
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    return asg_name


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


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
