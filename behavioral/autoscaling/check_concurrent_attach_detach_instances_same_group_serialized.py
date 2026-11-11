"""concurrent-attach-detach-instances-same-group-serialized."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-attach-detach-instances-same-group-serialized"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AttachInstances and DetachInstances on one Auto Scaling group are serialized: the
    group converges to the expected InService membership and DesiredCapacity 2."""
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    subnet = _default_subnet(ctx)
    ami = _get_al2023_ami(ctx)
    name_tag = ctx.unique_name("sim2real-asg-inst-")

    run_resp = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=3,
        MaxCount=3,
        SubnetId=subnet["SubnetId"],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ],
    )
    instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))
    ec2.get_waiter("instance_running").wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    instance_a, instance_b, instance_c = instance_ids

    lt_name = _create_dummy_launch_template(ctx)
    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=10,
        DesiredCapacity=0,
        AvailabilityZones=[subnet["AvailabilityZone"]],
        VPCZoneIdentifier=subnet["SubnetId"],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )

    autoscaling.attach_instances(
        AutoScalingGroupName=asg_name, InstanceIds=[instance_a, instance_b]
    )
    setup_membership = _wait_for_membership(
        ctx, asg_name, {instance_a, instance_b}, timeout_s=90.0
    )
    assert setup_membership == {instance_a, instance_b}, setup_membership

    with ThreadPoolExecutor(max_workers=2) as pool:
        attach_future = pool.submit(
            autoscaling.attach_instances,
            AutoScalingGroupName=asg_name,
            InstanceIds=[instance_c],
        )
        detach_future = pool.submit(
            autoscaling.detach_instances,
            AutoScalingGroupName=asg_name,
            InstanceIds=[instance_a],
            ShouldDecrementDesiredCapacity=True,
        )
        attach_future.result()
        detach_future.result()

    final_membership = _wait_for_membership(
        ctx, asg_name, {instance_b, instance_c}, timeout_s=120.0
    )
    assert final_membership == {instance_b, instance_c}, final_membership

    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 2, group["DesiredCapacity"]


def _create_dummy_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _default_subnet(ctx) -> dict:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet available in this account/region to launch the test "
            "instances into; provision a shared network VPC (or adapt to a non-default one) to "
            "close this gap"
        )
    return subnets[0]


def _get_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _wait_for_membership(
    ctx, asg_name: str, expected_ids: set[str], timeout_s: float = 60.0, interval_s: float = 3.0
) -> set[str]:
    autoscaling = ctx.client("autoscaling")
    current: set[str] = set()
    deadline = time.monotonic() + timeout_s
    # DetachInstances rejects a Pending instance; only InService counts as settled here.
    settled_states = {"InService"}
    while time.monotonic() < deadline:
        group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]
        current = {
            inst["InstanceId"]
            for inst in group["Instances"]
            if inst["LifecycleState"] in settled_states
        }
        if current == expected_ids:
            return current
        time.sleep(interval_s)
    return current


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
