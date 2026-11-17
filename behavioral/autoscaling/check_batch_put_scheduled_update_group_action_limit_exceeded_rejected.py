"""batch-put-scheduled-update-group-action-limit-exceeded-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "batch-put-scheduled-update-group-action-limit-exceeded-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]

_ACTION_LIMIT = 125
_BATCH_MAX = 50


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScheduledUpdateGroupAction is rejected with LimitExceeded once an Auto Scaling group
    already has the maximum of 125 scheduled actions, the count stays at the limit, and freeing
    one slot lets a new action succeed (positive control)."""
    autoscaling = ctx.client("autoscaling")
    subnet_ids = _default_subnet_ids(ctx, count=1)
    group = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        LaunchTemplate={"LaunchTemplateId": _create_launch_template(ctx)},
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=group, ForceDelete=True)
    )

    base_start_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)
    start_times = [base_start_time + dt.timedelta(minutes=i) for i in range(_ACTION_LIMIT)]
    action_names = [ctx.unique_name(f"sim2real-sa-{i}-") for i in range(_ACTION_LIMIT)]
    for offset in range(0, _ACTION_LIMIT, _BATCH_MAX):
        batch = list(zip(action_names[offset : offset + _BATCH_MAX], start_times[offset : offset + _BATCH_MAX]))
        resp = autoscaling.batch_put_scheduled_update_group_action(
            AutoScalingGroupName=group,
            ScheduledUpdateGroupActions=[
                {
                    "ScheduledActionName": name,
                    "StartTime": start_time,
                    "MinSize": 0,
                    "MaxSize": 0,
                    "DesiredCapacity": 0,
                }
                for name, start_time in batch
            ],
        )
        assert resp.get("FailedScheduledUpdateGroupActions", []) == [], (
            f"expected the batch to succeed atomically, got failures "
            f"{resp.get('FailedScheduledUpdateGroupActions')!r}"
        )

    existing = _list_action_names(ctx, group)
    assert existing == set(action_names), (
        f"expected the {_ACTION_LIMIT} created scheduled actions, got {len(existing)} present"
    )

    overflow_name = ctx.unique_name("sim2real-sa-overflow-")
    overflow_start_time = base_start_time + dt.timedelta(minutes=_ACTION_LIMIT)
    code, message = _error(
        lambda: autoscaling.put_scheduled_update_group_action(
            AutoScalingGroupName=group,
            ScheduledActionName=overflow_name,
            StartTime=overflow_start_time,
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
        )
    )
    assert code == "LimitExceeded", f"expected LimitExceeded past the per-group action cap, got {code}"
    expected_message = f"The maximum limit of {_ACTION_LIMIT} scheduled actions has been reached."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = _list_action_names(ctx, group)
    assert after_reject == set(action_names), (
        f"action set must stay at the {_ACTION_LIMIT} created actions after the rejected "
        f"PutScheduledUpdateGroupAction, got {len(after_reject)} present"
    )

    # Positive control: freeing one slot lets a new action succeed.
    autoscaling.batch_delete_scheduled_action(
        AutoScalingGroupName=group, ScheduledActionNames=[action_names[0]]
    )
    autoscaling.put_scheduled_update_group_action(
        AutoScalingGroupName=group,
        ScheduledActionName=overflow_name,
        StartTime=overflow_start_time,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
    )
    final = _list_action_names(ctx, group)
    expected_final = set(action_names[1:]) | {overflow_name}
    assert final == expected_final, (
        f"expected {overflow_name} to succeed once a slot was freed, got {len(final)} present"
    )


from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_action_names(ctx, group: str) -> set:
    autoscaling = ctx.client("autoscaling")
    paginator = autoscaling.get_paginator("describe_scheduled_actions")
    return {
        a["ScheduledActionName"]
        for page in paginator.paginate(AutoScalingGroupName=group)
        for a in page["ScheduledUpdateGroupActions"]
    }


def _default_subnet_ids(ctx, count: int = 1) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
