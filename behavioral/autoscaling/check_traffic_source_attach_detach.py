"""traffic-source-attach-detach."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "traffic-source-attach-detach"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachTrafficSources adds an ALB target group as a traffic source that becomes
    visible in DescribeTrafficSources, and DetachTrafficSources removes it again."""
    autoscaling = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    tg_name = ctx.unique_name("sim2real-behav-tg-")[:32]

    ami_id = _latest_al2023_ami(ctx)
    subnet_ids, vpc_id = _default_subnets(ctx)
    _create_launch_template(ctx, lt_name, ami_id)
    _create_zero_capacity_asg(ctx, asg_name, lt_name, subnet_ids)

    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=_MANAGED_TAGS_KV,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    before = autoscaling.describe_traffic_sources(AutoScalingGroupName=asg_name)[
        "TrafficSources"
    ]
    assert all(s["Identifier"] != tg_arn for s in before), (
        f"freshly created target group {tg_arn} already listed as a traffic source: {before!r}"
    )

    autoscaling.attach_traffic_sources(
        AutoScalingGroupName=asg_name,
        TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}],
    )

    def _attached() -> bool:
        sources = autoscaling.describe_traffic_sources(AutoScalingGroupName=asg_name)[
            "TrafficSources"
        ]
        return any(s["Identifier"] == tg_arn for s in sources)

    assert _poll_until(_attached, timeout_s=90, interval_s=3), (
        "traffic source never appeared in DescribeTrafficSources after attach"
    )
    attached_entry = [
        s
        for s in autoscaling.describe_traffic_sources(AutoScalingGroupName=asg_name)[
            "TrafficSources"
        ]
        if s["Identifier"] == tg_arn
    ][0]
    assert attached_entry["Type"] == "elbv2", (
        f"expected traffic source Type 'elbv2', got {attached_entry['Type']!r}"
    )

    autoscaling.detach_traffic_sources(
        AutoScalingGroupName=asg_name,
        TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}],
    )

    def _detached() -> bool:
        sources = autoscaling.describe_traffic_sources(AutoScalingGroupName=asg_name)[
            "TrafficSources"
        ]
        return all(s["Identifier"] != tg_arn for s in sources)

    assert _poll_until(_detached, timeout_s=90, interval_s=3), (
        "traffic source still present in DescribeTrafficSources after detach"
    )


# So a tag search finds any leftover if cleanup is interrupted.
_MANAGED_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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
            {"ResourceType": "launch-template", "Tags": _MANAGED_TAGS_KV}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    return lt_name


def _create_zero_capacity_asg(ctx, asg_name: str, lt_name: str, subnet_ids) -> str:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": tag["Key"],
                "Value": tag["Value"],
                "PropagateAtLaunch": False,
            }
            for tag in _MANAGED_TAGS_KV
        ],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
