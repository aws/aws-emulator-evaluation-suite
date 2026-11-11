"""scheduled-action-batch-lifecycle."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "scheduled-action-batch-lifecycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchPutScheduledUpdateGroupAction creates multiple actions atomically, visible via
    Describe, and both single DeleteScheduledAction and BatchDeleteScheduledAction remove
    them permanently."""
    asg = ctx.client("autoscaling")
    subnet_id, _vpc_id, _az = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=5,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    start_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)
    name_one = ctx.unique_name("sim2real-behav-sched-one-")
    name_two = ctx.unique_name("sim2real-behav-sched-two-")

    resp = asg.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledUpdateGroupActions=[
            {
                "ScheduledActionName": name_one,
                "StartTime": start_time,
                "MinSize": 1,
                "MaxSize": 3,
                "DesiredCapacity": 2,
            },
            {
                "ScheduledActionName": name_two,
                "Recurrence": "0 10 * * *",
                "MinSize": 0,
                "MaxSize": 4,
                "DesiredCapacity": 1,
            },
        ],
    )
    assert resp.get("FailedScheduledUpdateGroupActions", []) == [], (
        f"expected atomic batch success, got failures {resp.get('FailedScheduledUpdateGroupActions')!r}"
    )

    actions = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    action_names = {a["ScheduledActionName"] for a in actions}
    assert {name_one, name_two} <= action_names, f"expected both actions visible, got {action_names!r}"
    by_name = {a["ScheduledActionName"]: a for a in actions}
    assert by_name[name_one]["MinSize"] == 1 and by_name[name_one]["MaxSize"] == 3, (
        f"expected MinSize=1 MaxSize=3 for {name_one!r}, got {by_name[name_one]!r}"
    )
    assert by_name[name_two]["Recurrence"] == "0 10 * * *", (
        f"expected Recurrence='0 10 * * *' for {name_two!r}, got {by_name[name_two]['Recurrence']!r}"
    )

    # Single delete removes exactly one, leaving the other intact.
    asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=name_one)
    remaining_after_single = {
        a["ScheduledActionName"]
        for a in asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    }
    assert name_one not in remaining_after_single, (
        f"expected {name_one!r} gone after single delete, still present in {remaining_after_single!r}"
    )
    assert name_two in remaining_after_single, (
        f"expected {name_two!r} untouched by single delete, missing from {remaining_after_single!r}"
    )

    # Batch delete removes the rest permanently.
    batch_del_resp = asg.batch_delete_scheduled_action(
        AutoScalingGroupName=group_name, ScheduledActionNames=[name_two]
    )
    assert batch_del_resp.get("FailedScheduledActions", []) == [], (
        f"expected atomic batch delete success, got failures {batch_del_resp.get('FailedScheduledActions')!r}"
    )
    remaining_after_batch = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)[
        "ScheduledUpdateGroupActions"
    ]
    assert remaining_after_batch == [], f"expected no scheduled actions left, got {remaining_after_batch!r}"


def _default_subnet(ctx) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no network subnet available in this account/region")
    subnet = subnets[0]
    return subnet["SubnetId"], subnet["VpcId"], subnet["AvailabilityZone"]


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
