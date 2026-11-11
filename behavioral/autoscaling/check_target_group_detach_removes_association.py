"""target-group-detach-removes-association."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "target-group-detach-removes-association"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancerTargetGroups registers a target group with the ASG, visible via
    DescribeLoadBalancerTargetGroups; DetachLoadBalancerTargetGroups removes it again."""
    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")
    subnet = _default_subnet(ctx)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-")[:32],
        Protocol="HTTP",
        Port=80,
        VpcId=subnet["vpc_id"],
        TargetType="instance",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name, subnet["subnet_id"])

    asg.attach_load_balancer_target_groups(AutoScalingGroupName=group_name, TargetGroupARNs=[tg_arn])

    tgs = _poll_until(
        lambda: asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
            "LoadBalancerTargetGroups"
        ],
        lambda items: any(t["LoadBalancerTargetGroupARN"] == tg_arn for t in items),
        timeout_s=90,
        interval_s=3,
    )
    assert any(t["LoadBalancerTargetGroupARN"] == tg_arn for t in tgs), (
        f"target group not visible via DescribeLoadBalancerTargetGroups after attach: {tgs}"
    )

    asg.detach_load_balancer_target_groups(AutoScalingGroupName=group_name, TargetGroupARNs=[tg_arn])

    tgs_after = _poll_until(
        lambda: asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
            "LoadBalancerTargetGroups"
        ],
        lambda items: not any(t["LoadBalancerTargetGroupARN"] == tg_arn for t in items),
        timeout_s=90,
        interval_s=3,
    )
    assert not any(t["LoadBalancerTargetGroupARN"] == tg_arn for t in tgs_after), (
        f"target group still present via DescribeLoadBalancerTargetGroups after detach: {tgs_after}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"condition not met within {timeout_s}s; last={result!r}")


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
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
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": True}],
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
