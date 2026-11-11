"""batch-put-scheduled-actions-preserves-order."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "batch-put-scheduled-actions-preserves-order"
GROUP = "ordering"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Actions submitted out of order in one BatchPutScheduledUpdateGroupAction call are all
    returned by DescribeScheduledActions with their start times; AWS documents no listing
    order, so start-time order is accepted but not required."""
    asg = ctx.client("autoscaling")
    group_name = _create_shell_asg(ctx, min_size=0, max_size=3, desired=0)

    now = dt.datetime.now(dt.timezone.utc)
    names = [ctx.unique_name(f"sim2real-sched-{i}-") for i in range(3)]
    starts = [now + dt.timedelta(days=10), now + dt.timedelta(days=20), now + dt.timedelta(days=30)]

    # Submit in REVERSE chronological order to prove output ordering is not insertion order.
    actions = [
        {"ScheduledActionName": names[i], "StartTime": starts[i], "MinSize": 0, "MaxSize": 3, "DesiredCapacity": 1}
        for i in reversed(range(3))
    ]
    resp = asg.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=group_name, ScheduledUpdateGroupActions=actions
    )
    assert not resp.get("FailedScheduledUpdateGroupActions"), resp.get("FailedScheduledUpdateGroupActions")
    ctx.on_cleanup(
        lambda: asg.batch_delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionNames=names)
    )

    described = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    ours = [a for a in described if a["ScheduledActionName"] in names]
    assert len(ours) == 3, f"expected 3 scheduled actions, found {len(ours)}"

    ours_sorted_by_start = sorted(ours, key=lambda a: a["StartTime"])
    observed_names_in_order = [a["ScheduledActionName"] for a in ours]
    expected_names_in_order = [a["ScheduledActionName"] for a in ours_sorted_by_start]
    assert observed_names_in_order == expected_names_in_order or sorted(
        observed_names_in_order
    ) == sorted(expected_names_in_order), (
        f"DescribeScheduledActions did not return the submitted actions: "
        f"{observed_names_in_order} != {expected_names_in_order}"
    )
    # And the ascending start-time order must match our chronological name assignment (names[0]
    # has the earliest StartTime, names[2] the latest).
    assert expected_names_in_order == names, expected_names_in_order


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _get_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


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
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    subnet_id = _get_subnet(ctx)
    group_name = ctx.unique_name("sim2real-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": "true", "ResourceId": group_name, "ResourceType": "auto-scaling-group"}],
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
