"""scheduled-action-batch-create-delete."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "scheduled-action-batch-create-delete"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """BatchPutScheduledUpdateGroupAction creates multiple scheduled actions in one call,
    each visible via DescribeScheduledActions with the requested capacity fields, and each
    is individually removable via DeleteScheduledAction without touching the other."""
    autoscaling = ctx.client("autoscaling")
    asg_name = ctx.unique_name("sim2real-asg-")
    lt_name = ctx.unique_name("sim2real-lt-")
    action_a = ctx.unique_name("sim2real-sched-a-")
    action_b = ctx.unique_name("sim2real-sched-b-")

    ami_id = _latest_al2023_ami(ctx)
    subnet_ids, _vpc_id = _default_subnets(ctx)
    _create_launch_template(ctx, lt_name, ami_id)
    _create_zero_capacity_asg(ctx, asg_name, lt_name, subnet_ids)

    # Far-future start times: these must never actually fire during the check.
    far_future_a = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=370)
    far_future_b = far_future_a + datetime.timedelta(days=1)

    resp = autoscaling.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=asg_name,
        ScheduledUpdateGroupActions=[
            {
                "ScheduledActionName": action_a,
                "StartTime": far_future_a,
                "MinSize": 0,
                "MaxSize": 2,
                "DesiredCapacity": 1,
            },
            {
                "ScheduledActionName": action_b,
                "StartTime": far_future_b,
                "MinSize": 0,
                "MaxSize": 3,
                "DesiredCapacity": 2,
            },
        ],
    )
    assert resp.get("FailedScheduledUpdateGroupActions", []) == [], (
        f"unexpected failures on batch put: {resp.get('FailedScheduledUpdateGroupActions')}"
    )
    ctx.on_cleanup(
        lambda: autoscaling.batch_delete_scheduled_action(
            AutoScalingGroupName=asg_name,
            ScheduledActionNames=[action_a, action_b],
        )
    )

    described = autoscaling.describe_scheduled_actions(AutoScalingGroupName=asg_name)[
        "ScheduledUpdateGroupActions"
    ]
    by_name = {a["ScheduledActionName"]: a for a in described}
    assert action_a in by_name and action_b in by_name, (
        f"expected both scheduled actions present, got names {list(by_name)}"
    )
    assert by_name[action_a]["MaxSize"] == 2 and by_name[action_a]["DesiredCapacity"] == 1, (
        f"action_a fields wrong: {by_name[action_a]}"
    )
    assert by_name[action_b]["MaxSize"] == 3 and by_name[action_b]["DesiredCapacity"] == 2, (
        f"action_b fields wrong: {by_name[action_b]}"
    )

    autoscaling.delete_scheduled_action(
        AutoScalingGroupName=asg_name, ScheduledActionName=action_a
    )

    after_delete_a = autoscaling.describe_scheduled_actions(AutoScalingGroupName=asg_name)[
        "ScheduledUpdateGroupActions"
    ]
    names_after = {a["ScheduledActionName"] for a in after_delete_a}
    assert action_a not in names_after, "deleted scheduled action still present"
    assert action_b in names_after, "unrelated scheduled action was removed too"

    autoscaling.delete_scheduled_action(
        AutoScalingGroupName=asg_name, ScheduledActionName=action_b
    )
    after_delete_b = autoscaling.describe_scheduled_actions(AutoScalingGroupName=asg_name)[
        "ScheduledUpdateGroupActions"
    ]
    assert all(a["ScheduledActionName"] not in (action_a, action_b) for a in after_delete_b), (
        f"a deleted scheduled action reappeared: {after_delete_b}"
    )

    # A repeat delete on an id that is now gone must fail, not silently no-op: the same
    # ValidationError AWS returns for a name that was never created.
    from botocore.exceptions import ClientError

    try:
        autoscaling.delete_scheduled_action(
            AutoScalingGroupName=asg_name, ScheduledActionName=action_b
        )
        raise AssertionError(
            "expected DeleteScheduledAction on an already-deleted action to raise ValidationError"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationError", f"expected ValidationError, got {code}"
        assert message == "Scheduled action name not found", (
            f"unexpected ValidationError message: {message!r}"
        )


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnets(ctx, count: int = 2):

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]], subnets[0]["VpcId"]


def _create_launch_template(ctx, lt_name: str, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    return lt_name


def _create_zero_capacity_asg(ctx, asg_name: str, lt_name: str, subnet_ids) -> str:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": "sim2real-behav", "Value": asg_name, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
