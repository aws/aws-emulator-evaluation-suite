"""traffic-source-attach-detach-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "traffic-source-attach-detach-lifecycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachTrafficSources registers an ELBv2 target group as a traffic source, visible via
    DescribeTrafficSources; DetachTrafficSources removes the association again."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")
    subnet = _default_subnet(ctx)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-b-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=subnet["vpc_id"],
        TargetType="instance",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name, subnet["subnet_id"])

    asg.attach_traffic_sources(
        AutoScalingGroupName=group_name,
        TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}],
    )

    sources = _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda srcs: any(s["Identifier"] == tg_arn for s in srcs),
        timeout_s=90,
        interval_s=3,
    )
    assert any(s["Identifier"] == tg_arn for s in sources), (
        f"target group not visible via DescribeTrafficSources after attach: {sources}"
    )

    asg.detach_traffic_sources(
        AutoScalingGroupName=group_name,
        TrafficSources=[{"Identifier": tg_arn, "Type": "elbv2"}],
    )

    sources_after = _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda srcs: not any(s["Identifier"] == tg_arn for s in srcs),
        timeout_s=90,
        interval_s=3,
    )
    assert not any(s["Identifier"] == tg_arn for s in sources_after), (
        f"target group still present via DescribeTrafficSources after detach: {sources_after}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s; last={result!r}")


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"no subnets available in VPC {vpc_id} in this account/region")
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"]}


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


def _create_empty_asg(ctx, name: str, subnet_id: str) -> str:
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
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
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as e:
            err = e.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)
    return name



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
