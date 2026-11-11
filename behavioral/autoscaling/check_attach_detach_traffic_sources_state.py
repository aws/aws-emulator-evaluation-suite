"""attach-detach-traffic-sources-state."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "attach-detach-traffic-sources-state"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachTrafficSources registers a traffic source visible via DescribeTrafficSources,
    and DetachTrafficSources removes it."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    subnet_id, vpc_id, _az = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    tg_name = ctx.unique_name("sim2real-behav-tg-")[:32]
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    before = asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"]
    before_identifiers = {s["Identifier"] for s in before}
    assert tg_arn not in before_identifiers, (
        f"expected {tg_arn} absent before attach, got {before_identifiers!r}"
    )

    asg.attach_traffic_sources(
        AutoScalingGroupName=group_name, TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}]
    )

    attached = _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda sources: any(s["Identifier"] == tg_arn for s in sources),
        timeout_s=60.0,
        interval_s=3.0,
    )
    identifiers = {s["Identifier"] for s in attached}
    assert tg_arn in identifiers, f"expected {tg_arn} tracked after attach, got {identifiers!r}"
    attached_entry = next(s for s in attached if s["Identifier"] == tg_arn)
    assert attached_entry["Type"] == "elbv2", (
        f"expected Type 'elbv2' for {tg_arn}, got {attached_entry['Type']!r}"
    )

    asg.detach_traffic_sources(
        AutoScalingGroupName=group_name, TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}]
    )

    _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda sources: tg_arn not in {s["Identifier"] for s in sources},
        timeout_s=60.0,
        interval_s=3.0,
    )


def _default_subnet(ctx) -> tuple[str, str, str]:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no network subnet available in this account/region")
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
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")



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
