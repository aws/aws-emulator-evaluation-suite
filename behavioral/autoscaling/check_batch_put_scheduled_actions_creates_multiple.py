"""batch-put-scheduled-actions-creates-multiple."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-scheduled-actions-creates-multiple"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchPutScheduledUpdateGroupAction atomically creates several scheduled actions that
    all appear in DescribeScheduledActions."""
    asg = ctx.client("autoscaling")
    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name)

    base_time = datetime.now(timezone.utc) + timedelta(days=30)
    names = [ctx.unique_name(f"sim2real-behav-sched-{i}-") for i in range(3)]
    actions = [
        {
            "ScheduledActionName": names[i],
            "StartTime": base_time + timedelta(hours=i),
            "MinSize": 0,
            "MaxSize": 1,
            "DesiredCapacity": 1,
        }
        for i in range(3)
    ]

    resp = asg.batch_put_scheduled_update_group_action(
        AutoScalingGroupName=group_name, ScheduledUpdateGroupActions=actions
    )
    assert resp.get("FailedScheduledUpdateGroupActions", []) == [], (
        f"unexpected per-action failures: {resp.get('FailedScheduledUpdateGroupActions')}"
    )

    def _cleanup_actions():
        resp = asg.batch_delete_scheduled_action(AutoScalingGroupName=group_name, ScheduledActionNames=names)
        failed = resp.get("FailedScheduledActions", [])
        if failed:
            raise AssertionError(f"scheduled action delete failed: {failed}")

    ctx.on_cleanup(_cleanup_actions)

    listed = asg.describe_scheduled_actions(AutoScalingGroupName=group_name)["ScheduledUpdateGroupActions"]
    by_name = {a["ScheduledActionName"]: a for a in listed if a["ScheduledActionName"] in names}
    assert len(by_name) == 3, (
        f"expected all 3 batch-created actions visible, got {sorted(by_name)} of {names}"
    )
    for i, name in enumerate(names):
        action = by_name[name]
        assert action["MinSize"] == 0 and action["MaxSize"] == 1 and action["DesiredCapacity"] == 1, (
            f"{name}: capacity fields did not round-trip, got Min={action['MinSize']} "
            f"Max={action['MaxSize']} Desired={action['DesiredCapacity']}"
        )
        expected_start = (base_time + timedelta(hours=i)).replace(microsecond=0)
        assert action["StartTime"].replace(microsecond=0) == expected_start, (
            f"{name}: StartTime did not round-trip, got {action['StartTime']} expected {expected_start}"
        )


# ===== helpers =====
def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"no subnets available in VPC {vpc_id}"
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
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
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
