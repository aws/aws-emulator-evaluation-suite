"""detach-instances-state."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "detach-instances-state"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachInstances removes an attached instance from group membership reflected in
    DescribeAutoScalingGroups, honoring the decrement-desired-capacity flag."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

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
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=2,
        MaxCount=2,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-instance-")}],
            }
        ],
    )
    instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    asg.attach_instances(InstanceIds=instance_ids, AutoScalingGroupName=group_name)

    attached_group = _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"][0],
        lambda g: len(g["Instances"]) == 2,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert attached_group["DesiredCapacity"] == 2, (
        f"AttachInstances should raise desired capacity by the count attached, got {attached_group['DesiredCapacity']!r}"
    )
    attached_ids = {i["InstanceId"] for i in attached_group["Instances"]}
    assert attached_ids == set(instance_ids), (
        f"expected group membership {set(instance_ids)!r} after AttachInstances, got {attached_ids!r}"
    )

    # DetachInstances only accepts instances in InService/Standby (or the *:Retained states) -
    # a freshly attached instance is transiently "Pending" during health-check bootstrap and
    # real AWS rejects a detach issued during that window with a ValidationError, so settle
    # first rather than racing DetachInstances against AttachInstances.
    settled_group = _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"][0],
        lambda g: all(
            i["LifecycleState"] in ("InService", "Standby") for i in g["Instances"]
        ) and len(g["Instances"]) == 2,
        timeout_s=180.0,
        interval_s=5.0,
    )
    settled_states = {i["InstanceId"]: i["LifecycleState"] for i in settled_group["Instances"]}
    assert all(s in ("InService", "Standby") for s in settled_states.values()), (
        f"attached instances never settled into InService/Standby before detach: {settled_states!r}"
    )

    detach_id = instance_ids[0]
    remain_id = instance_ids[1]
    asg.detach_instances(
        InstanceIds=[detach_id], AutoScalingGroupName=group_name, ShouldDecrementDesiredCapacity=True
    )

    after_detach = _poll_until(
        lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"][0],
        lambda g: len(g["Instances"]) == 1,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert after_detach["DesiredCapacity"] == 1, (
        f"decrement flag should lower desired capacity by 1, got {after_detach['DesiredCapacity']!r}"
    )
    remaining_ids = {i["InstanceId"] for i in after_detach["Instances"]}
    assert remaining_ids == {remain_id}, f"expected only {remain_id} left in group, got {remaining_ids!r}"

    # detached instance must still exist standalone (not terminated by the detach).
    described = ec2.describe_instances(InstanceIds=[detach_id])["Reservations"][0]["Instances"][0]
    assert described["State"]["Name"] in ("running", "pending"), (
        f"detached instance should remain alive, got state {described['State']!r}"
    )


def _default_subnet(ctx) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
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
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
