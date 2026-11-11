"""detach-instances-from-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "detach-instances-from-group"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachInstances removes a real, managed instance from the ASG's managed instance
    set: it disappears from DescribeAutoScalingGroups' Instances list and the group's
    DesiredCapacity is decremented (ShouldDecrementDesiredCapacity=True)."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    asg_name = ctx.unique_name("sim2real-asg-")
    lt_name = ctx.unique_name("sim2real-lt-")

    ami_id = _latest_al2023_ami(ctx)
    subnet_ids, _vpc_id = _default_subnets(ctx)
    _create_launch_template(ctx, lt_name, ami_id)

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[
            {
                "Key": "sim2real",
                "Value": "true",
                "ResourceType": "auto-scaling-group",
                "ResourceId": asg_name,
                "PropagateAtLaunch": True,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )

    def _group() -> dict:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        assert len(groups) == 1, (
            f"expected exactly one group named {asg_name!r}, got {len(groups)}"
        )
        return groups[0]

    def _has_in_service_instance() -> bool:
        instances = _group()["Instances"]
        return any(i["LifecycleState"] == "InService" for i in instances)

    assert _poll_until(_has_in_service_instance, timeout_s=300, interval_s=10), (
        "no instance reached InService in the Auto Scaling group within 300s"
    )
    instance_id = [
        i["InstanceId"] for i in _group()["Instances"] if i["LifecycleState"] == "InService"
    ][0]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    autoscaling.detach_instances(
        AutoScalingGroupName=asg_name,
        InstanceIds=[instance_id],
        ShouldDecrementDesiredCapacity=True,
    )

    def _detached() -> bool:
        group = _group()
        still_member = any(i["InstanceId"] == instance_id for i in group["Instances"])
        return not still_member and group["DesiredCapacity"] == 0

    assert _poll_until(_detached, timeout_s=120, interval_s=5), (
        "detached instance still listed in DescribeAutoScalingGroups or "
        "DesiredCapacity was not decremented"
    )

    final_group = _group()
    assert final_group["DesiredCapacity"] == 0, (
        f"expected DesiredCapacity 0 after decrementing detach, got "
        f"{final_group['DesiredCapacity']!r}"
    )
    assert all(i["InstanceId"] != instance_id for i in final_group["Instances"]), (
        f"detached instance {instance_id} is still present in "
        f"{[i['InstanceId'] for i in final_group['Instances']]!r}"
    )


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnets(ctx, count: int = 2):

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]], subnets[0]["VpcId"]


def _create_launch_template(ctx, lt_name: str, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real", "Value": "true"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    return lt_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
