"""scheduled-action-delete-single."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-delete-single"
GROUP = "state-machine"
SERVICES = ["autoscaling"]

_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A scheduled action created via PutScheduledUpdateGroupAction is removed by
    DeleteScheduledAction and disappears from DescribeScheduledActions."""
    asg = ctx.client("autoscaling")
    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name)

    action_name = ctx.unique_name("sim2real-behav-sched-")
    start_time = datetime.now(timezone.utc) + timedelta(days=30)
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=action_name,
        StartTime=start_time,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
    )

    actions = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)[
        "ScheduledUpdateGroupActions"
    ]
    assert any(a["ScheduledActionName"] == action_name for a in actions), (
        f"scheduled action not visible after PutScheduledUpdateGroupAction: {actions}"
    )

    asg.delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionName=action_name)

    actions_after = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)[
        "ScheduledUpdateGroupActions"
    ]
    assert not any(a["ScheduledActionName"] == action_name for a in actions_after), (
        f"scheduled action still present after DeleteScheduledAction: {actions_after}"
    )

    try:
        asg.delete_scheduled_action(
            AutoScalingGroupName=group_name, ScheduledActionName=action_name
        )
        raise AssertionError(
            "expected a second DeleteScheduledAction on the now-deleted action name "
            "to raise ValidationError"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationError", (
            f"expected ValidationError re-deleting a gone scheduled action, got {code}"
        )
        assert message == "Scheduled action name not found", (
            f"unexpected message re-deleting a gone scheduled action: {message!r}"
        )


# ===== helpers =====
def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return subnets[0]["SubnetId"]


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


def _create_empty_asg(ctx, name: str) -> str:
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    subnet_id = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
    )

    def _cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
