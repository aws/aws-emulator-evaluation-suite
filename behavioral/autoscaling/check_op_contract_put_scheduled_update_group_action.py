"""op-contract-put-scheduled-update-group-action."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-put-scheduled-update-group-action"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScheduledUpdateGroupAction persists a future one-time scaling schedule with the
    exact MinSize/MaxSize/DesiredCapacity given; scheduling into the past is rejected and
    creates nothing."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-schedact-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=5, desired=0)

    action_name = ctx.unique_name("sim2real-behav-action-")
    start_time = datetime.now(timezone.utc) + timedelta(hours=2)
    resp = autoscaling.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=action_name,
        StartTime=start_time,
        MinSize=1,
        MaxSize=4,
        DesiredCapacity=2,
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_scheduled_action(AutoScalingGroupName=name, ScheduledActionName=action_name)
    )
    # PutScheduledUpdateGroupAction's own response does not carry ScheduledActionARN on real AWS
    # (it is a bare acknowledgement); the ARN is only visible via DescribeScheduledActions.
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from put_scheduled_update_group_action, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    actions = autoscaling.describe_scheduled_actions(AutoScalingGroupName=name, ScheduledActionNames=[action_name])[
        "ScheduledUpdateGroupActions"
    ]
    assert len(actions) == 1, f"expected exactly 1 scheduled action named {action_name}, got {len(actions)}"
    action = actions[0]
    assert "ScheduledActionARN" in action and action["ScheduledActionARN"], (
        f"expected a non-empty ScheduledActionARN on the described action, got {action.get('ScheduledActionARN')!r}"
    )
    assert action["MinSize"] == 1, f"expected MinSize=1, got {action['MinSize']}"
    assert action["MaxSize"] == 4, f"expected MaxSize=4, got {action['MaxSize']}"
    assert action["DesiredCapacity"] == 2, f"expected DesiredCapacity=2, got {action['DesiredCapacity']}"
    # StartTime round-trips to the second.
    assert action["StartTime"].replace(microsecond=0) == start_time.replace(microsecond=0), (
        f"expected StartTime {start_time!r} to round-trip, got {action['StartTime']!r}"
    )

    # Error boundary: scheduling an action to start in the past is rejected by the service
    # ("If you try to schedule your action in the past, Amazon EC2 Auto Scaling returns an
    # error message.") and no new scheduled action is created for it.
    past_action_name = ctx.unique_name("sim2real-behav-pastaction-")
    past_time = datetime.now(timezone.utc) - timedelta(hours=1)
    code, message = _error(
        lambda: autoscaling.put_scheduled_update_group_action(
            AutoScalingGroupName=name,
            ScheduledActionName=past_action_name,
            StartTime=past_time,
            MinSize=1,
            MaxSize=4,
            DesiredCapacity=2,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Given start time is in the past"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    remaining = autoscaling.describe_scheduled_actions(AutoScalingGroupName=name)["ScheduledUpdateGroupActions"]
    assert all(a["ScheduledActionName"] != past_action_name for a in remaining), (
        f"expected no scheduled action named {past_action_name} after its rejected creation, but found one"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message).

    Raises on unexpected success so accepting refused input is never reported as a code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": name}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real-behav", "Value": name, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
