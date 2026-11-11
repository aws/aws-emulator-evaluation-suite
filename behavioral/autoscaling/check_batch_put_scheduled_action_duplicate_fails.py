"""batch-put-scheduled-action-duplicate-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-put-scheduled-action-duplicate-fails"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchPutScheduledUpdateGroupAction with an existing name fails the whole batch atomically:
    both entries land in FailedScheduledUpdateGroupActions, the existing action is unmodified and
    the new name is not created; a batch with only a new name succeeds."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    # CreateAutoScalingGroup rejects a group with no launch source; any minimal template works.
    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": _latest_al2023_ami(ctx),
            "InstanceType": "t3.micro",
        },
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    group_name = ctx.unique_name("sim2real-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name))

    existing_name = ctx.unique_name("sim2real-sched-existing-")
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=existing_name,
        Recurrence="0 0 1 1 *",
        MinSize=0,
        MaxSize=2,
    )
    ctx.on_cleanup(
        lambda: asg.delete_scheduled_action(
            AutoScalingGroupName=group_name, ScheduledActionName=existing_name
        )
    )
    before = _describe_action(asg, group_name, existing_name)
    assert before["MaxSize"] == 2, f"expected the pre-existing action's MaxSize to be 2, got {before!r}"

    new_name = ctx.unique_name("sim2real-sched-new-")
    resp = asg.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledUpdateGroupActions=[
            {
                # Existing name with different parameters: a conflict, not an upsert.
                "ScheduledActionName": existing_name,
                "Recurrence": "0 0 1 1 *",
                "MinSize": 0,
                "MaxSize": 9,
            },
            {
                "ScheduledActionName": new_name,
                "Recurrence": "0 0 1 1 *",
                "MinSize": 0,
                "MaxSize": 3,
            },
        ],
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: asg.delete_scheduled_action(
                AutoScalingGroupName=group_name, ScheduledActionName=new_name
            )
        )
    )
    failed = resp.get("FailedScheduledUpdateGroupActions", [])
    failed_names = {f["ScheduledActionName"] for f in failed}
    assert existing_name in failed_names, (
        "a batch reusing an existing scheduled-action name must be reported "
        f"in FailedScheduledUpdateGroupActions, got: {failed!r}"
    )
    assert new_name in failed_names, (
        "when one entry in a batch conflicts, real AWS rejects the whole "
        "batch atomically, so the brand-new name in the same batch must "
        f"also be reported as failed, got: {failed!r}"
    )

    after = _describe_action(asg, group_name, existing_name)
    assert after["MaxSize"] == 2, "existing scheduled action must be left unmodified when reported as failed"
    assert not _action_exists(asg, group_name, new_name), (
        "the brand-new name must not have been created when its batch was "
        "rejected due to a conflicting entry"
    )

    # Positive control on a second group: after a conflict, AWS keeps failing new names on the
    # conflicted group, so the control needs a group that has never seen a conflict.
    lt_name2 = ctx.unique_name("sim2real-lt2-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name2,
        LaunchTemplateData={
            "ImageId": _latest_al2023_ami(ctx),
            "InstanceType": "t3.micro",
        },
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name2))

    group_name2 = ctx.unique_name("sim2real-asg2-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name2,
        LaunchTemplate={"LaunchTemplateName": lt_name2},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name2))

    another_name = ctx.unique_name("sim2real-sched-another-")
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: asg.delete_scheduled_action(
                AutoScalingGroupName=group_name2, ScheduledActionName=another_name
            )
        )
    )
    # A just-created group can transiently fail a valid batch entry while it propagates.
    def _try_batch_put():
        return asg.batch_put_scheduled_update_group_action(
            AutoScalingGroupName=group_name2,
            ScheduledUpdateGroupActions=[
                {
                    "ScheduledActionName": another_name,
                    "Recurrence": "0 0 1 1 *",
                    "MinSize": 0,
                    "MaxSize": 3,
                }
            ],
        )

    resp2 = _try_batch_put()
    last_failed = resp2.get("FailedScheduledUpdateGroupActions", [])
    deadline = time.time() + 60
    while last_failed and time.time() < deadline:
        time.sleep(3)
        resp2 = _try_batch_put()
        last_failed = resp2.get("FailedScheduledUpdateGroupActions", [])
    assert last_failed == [], (
        "a batch containing only a brand-new, non-conflicting scheduled-"
        f"action name on a group with no prior conflict must succeed with "
        f"no reported failures, got: {last_failed!r}"
    )
    created2 = _describe_action(asg, group_name2, another_name)
    assert created2["MaxSize"] == 3, f"expected the new action's MaxSize to be 3, got {created2!r}"




def _describe_action(asg, group_name: str, name: str) -> dict:
    actions = asg.describe_scheduled_actions(
        AutoScalingGroupName=group_name, ScheduledActionNames=[name]
    )["ScheduledUpdateGroupActions"]
    assert len(actions) == 1, f"expected exactly one scheduled action named {name}"
    return actions[0]


def _action_exists(asg, group_name: str, name: str) -> bool:
    actions = asg.describe_scheduled_actions(
        AutoScalingGroupName=group_name, ScheduledActionNames=[name]
    )["ScheduledUpdateGroupActions"]
    return len(actions) > 0


def _ignore_not_found(fn) -> None:
    """Run a delete; only Auto Scaling's "not found" ValidationError means already gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return azs[0]["ZoneName"]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


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
