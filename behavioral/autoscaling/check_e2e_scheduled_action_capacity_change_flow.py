"""e2e-scheduled-action-capacity-change-flow."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "e2e-scheduled-action-capacity-change-flow"
GROUP = "e2e"
SERVICES = ["autoscaling"]


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scheduled-scaling.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A scheduled action leaves the group unchanged before its StartTime and, once it elapses, applies
    its Min/Max/DesiredCapacity with real instances launching to match."""
    autoscaling = ctx.client("autoscaling")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_ids[0], HealthCheckType="EC2", HealthCheckGracePeriod=60,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    baseline = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    baseline_capacity = (baseline["MinSize"], baseline["MaxSize"], baseline["DesiredCapacity"])
    assert baseline_capacity == (0, 1, 0), f"baseline capacity was {baseline_capacity}, expected (0, 1, 0)"

    start_time = datetime.now(timezone.utc) + timedelta(seconds=90)
    action_name = ctx.unique_name("sim2real-sched-")
    autoscaling.put_scheduled_update_group_action(
        AutoScalingGroupName=asg_name, ScheduledActionName=action_name,
        StartTime=start_time, MinSize=1, MaxSize=2, DesiredCapacity=2,
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: autoscaling.delete_scheduled_action(AutoScalingGroupName=asg_name, ScheduledActionName=action_name), "ValidationError", message="not found"))

    before = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    before_capacity = (before["MinSize"], before["MaxSize"], before["DesiredCapacity"])
    assert before_capacity == baseline_capacity, (
        f"capacity is already {before_capacity} right after PutScheduledUpdateGroupAction, before "
        f"its StartTime has elapsed; a scheduled action must not apply early, expected it to still "
        f"read {baseline_capacity}"
    )

    final = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0],
        lambda grp: grp["DesiredCapacity"] == 2,
        timeout_s=420.0, interval_s=10.0,
    )
    assert final["MinSize"] == 1, f"MinSize is {final['MinSize']} once the scheduled action fired, expected 1"
    assert final["MaxSize"] == 2, f"MaxSize is {final['MaxSize']} once the scheduled action fired, expected 2"
    assert final["DesiredCapacity"] == 2, (
        f"DesiredCapacity is {final['DesiredCapacity']} once the scheduled action fired, expected 2"
    )

    in_service_ids = _poll_until(
        lambda: [
            i["InstanceId"]
            for i in autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
            ["AutoScalingGroups"][0]["Instances"]
            if i["LifecycleState"] == "InService"
        ],
        lambda ids: len(ids) == 2,
        timeout_s=300.0, interval_s=10.0,
    )
    assert len(in_service_ids) == 2, f"expected 2 InService instance ids, got {in_service_ids}"

    reservations = ec2.describe_instances(InstanceIds=in_service_ids)["Reservations"]
    instances = [inst for r in reservations for inst in r["Instances"]]
    assert len(instances) == 2, (
        f"ec2:DescribeInstances returned {len(instances)} instances for {in_service_ids}, expected 2"
    )
    running_states = [inst["State"]["Name"] for inst in instances]
    assert running_states == ["running", "running"], (
        f"expected both scaled-up instances running at the EC2 destination, got states {running_states}"
    )
    for inst in instances:
        tag_map = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        assert tag_map.get("aws:autoscaling:groupName") == asg_name, (
            f"instance {inst['InstanceId']} is tagged aws:autoscaling:groupName="
            f"{tag_map.get('aws:autoscaling:groupName')!r} at EC2, expected {asg_name!r}"
        )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets], sg


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
