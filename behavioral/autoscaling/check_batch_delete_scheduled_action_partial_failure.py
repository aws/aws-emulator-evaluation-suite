"""batch-delete-scheduled-action-partial-failure."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-scheduled-action-partial-failure"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """BatchDeleteScheduledAction surfaces a per-name failure for a nonexistent scheduled
    action while still deleting the real one in the same batch (partial-failure semantics,
    no top-level error)."""
    asg = ctx.client("autoscaling")
    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name)

    real_name = ctx.unique_name("sim2real-behav-sched-real-")
    bogus_name = ctx.unique_name("sim2real-behav-sched-bogus-")
    asg.put_scheduled_update_group_action(
        AutoScalingGroupName=group_name,
        ScheduledActionName=real_name,
        StartTime=datetime.now(timezone.utc) + timedelta(days=30),
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
    )

    before = asg.describe_scheduled_actions(
        AutoScalingGroupName=group_name, ScheduledActionNames=[real_name]
    )["ScheduledUpdateGroupActions"]
    assert len(before) == 1 and before[0]["ScheduledActionName"] == real_name, (
        f"positive control: the real scheduled action must exist before the batch delete: {before}"
    )

    resp = asg.batch_delete_scheduled_action(
        AutoScalingGroupName=group_name, ScheduledActionNames=[real_name, bogus_name]
    )
    failed = resp.get("FailedScheduledActions", [])
    failed_names = {f["ScheduledActionName"] for f in failed}
    assert len(failed) == 1, f"expected exactly one per-item failure entry, got {failed!r}"
    assert bogus_name in failed_names, (
        f"expected the nonexistent scheduled action to be reported as a per-item failure: {resp}"
    )
    assert real_name not in failed_names, (
        f"the real scheduled action should not be reported as failed: {resp}"
    )
    bogus_failure = next(f for f in failed if f["ScheduledActionName"] == bogus_name)
    assert bogus_failure.get("ErrorCode") or bogus_failure.get("ErrorMessage"), (
        f"the per-item failure entry must carry an error code/message: {bogus_failure}"
    )

    remaining = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    assert not any(a["ScheduledActionName"] == real_name for a in remaining), (
        "real scheduled action was not actually deleted despite not being in FailedScheduledActions"
    )


# ===== helpers =====
def _default_subnet(ctx) -> str:
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
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
    )

    def _cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
