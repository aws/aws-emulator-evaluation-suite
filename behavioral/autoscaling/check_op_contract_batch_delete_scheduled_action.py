"""op-contract-batchDeleteScheduledAction."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-batchDeleteScheduledAction"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteScheduledAction deletes the valid names and reports the invalid
    ones in-band via FailedScheduledActions, without raising."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    start_time = datetime.now(timezone.utc) + timedelta(hours=2)
    action_name = ctx.unique_name("sim2real-behav-sched-")
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=action_name,
        StartTime=start_time,
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=1,
    )

    present = asg.describe_scheduled_actions(
        AutoScalingGroupName=group_name, ScheduledActionNames=[action_name]
    )["ScheduledUpdateGroupActions"]
    assert len(present) == 1 and present[0]["ScheduledActionName"] == action_name

    missing_name = ctx.unique_name("sim2real-behav-missing-")
    resp = asg.batch_delete_scheduled_action(
        AutoScalingGroupName=group_name,
        ScheduledActionNames=[action_name, missing_name],
    )

    failed = resp["FailedScheduledActions"]
    assert len(failed) == 1, f"expected exactly one failure entry, got {failed!r}"
    assert failed[0]["ScheduledActionName"] == missing_name
    assert failed[0].get("ErrorCode") or failed[0].get("ErrorMessage"), (
        "failure entry must carry an error code/message"
    )

    remaining = asg.describe_scheduled_actions(
        AutoScalingGroupName=group_name, ScheduledActionNames=[action_name]
    )["ScheduledUpdateGroupActions"]
    assert remaining == [], "the valid scheduled action must have been deleted"


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        # No VPC is tagged as the account default (e.g. a freshly provisioned
        # account) -- adopt any VPC present rather than depending on one.
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")

    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the adopted VPC")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_delete_group)
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
