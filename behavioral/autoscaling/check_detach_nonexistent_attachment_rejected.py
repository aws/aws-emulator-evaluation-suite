"""detach-nonexistent-attachment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detach-nonexistent-attachment-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachLoadBalancers, DetachTrafficSources and DetachLoadBalancerTargetGroups reject a
    resource never attached to the group instead of a silent no-op; each first detaches a really
    attached resource successfully, so the rejection is about "never attached"."""
    asg = ctx.client("autoscaling")
    elb = ctx.client("elb")
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- positive controls: each operation must succeed on a resource that IS attached ---
    clb_name = ctx.unique_name("sim2real-behav-clb-")
    elb.create_load_balancer(
        LoadBalancerName=clb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=[subnet_id],
        Scheme="internal",
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=clb_name))
    elb.add_tags(
        LoadBalancerNames=[clb_name],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    asg.attach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[clb_name])
    _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda items: any(lb["LoadBalancerName"] == clb_name for lb in items),
        timeout_s=90,
        description="attached classic load balancer visible via DescribeLoadBalancers",
    )
    asg.detach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[clb_name])
    _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda items: not any(lb["LoadBalancerName"] == clb_name for lb in items),
        timeout_s=90,
        description="detached classic load balancer removed from DescribeLoadBalancers",
    )

    positive_tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, positive_tg_arn))
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=group_name, TargetGroupARNs=[positive_tg_arn])
    _poll_until(
        lambda: asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
            "LoadBalancerTargetGroups"
        ],
        lambda items: any(t["LoadBalancerTargetGroupARN"] == positive_tg_arn for t in items),
        timeout_s=90,
        description="attached target group visible via DescribeLoadBalancerTargetGroups",
    )
    asg.detach_load_balancer_target_groups(AutoScalingGroupName=group_name, TargetGroupARNs=[positive_tg_arn])
    _poll_until(
        lambda: asg.describe_load_balancer_target_groups(AutoScalingGroupName=group_name)[
            "LoadBalancerTargetGroups"
        ],
        lambda items: not any(t["LoadBalancerTargetGroupARN"] == positive_tg_arn for t in items),
        timeout_s=90,
        description="detached target group removed from DescribeLoadBalancerTargetGroups",
    )

    asg.attach_traffic_sources(
        AutoScalingGroupName=group_name,
        TrafficSources=[{"Identifier": positive_tg_arn, "Type": "elbv2"}],
    )
    _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda items: any(s["Identifier"] == positive_tg_arn for s in items),
        timeout_s=90,
        description="attached traffic source visible via DescribeTrafficSources",
    )
    asg.detach_traffic_sources(
        AutoScalingGroupName=group_name,
        TrafficSources=[{"Identifier": positive_tg_arn, "Type": "elbv2"}],
    )
    _poll_until(
        lambda: asg.describe_traffic_sources(AutoScalingGroupName=group_name)["TrafficSources"],
        lambda items: not any(s["Identifier"] == positive_tg_arn for s in items),
        timeout_s=90,
        description="detached traffic source removed from DescribeTrafficSources",
    )

    # --- negative: the same operations must reject a resource that was NEVER attached ---
    tg_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:"
        "targetgroup/sim2real-never-attached-tg/0123456789abcdef"
    )

    never_attached_clb = "sim2real-never-attached-clb"
    error = _error(
        lambda: asg.detach_load_balancers(
            AutoScalingGroupName=group_name, LoadBalancerNames=[never_attached_clb]
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    expected = f"Trying to remove Load Balancers that are not part of the group: {never_attached_clb}"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    # DetachLoadBalancerTargetGroups and DetachTrafficSources share one refusal message.
    expected = f"Trying to remove Target Groups that are not part of the group: {tg_arn}"
    error = _error(
        lambda: asg.detach_load_balancer_target_groups(
            AutoScalingGroupName=group_name, TargetGroupARNs=[tg_arn]
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    error = _error(
        lambda: asg.detach_traffic_sources(
            AutoScalingGroupName=group_name, TrafficSources=[{"Identifier": tg_arn}]
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected success raises, so accepting a
    call AWS refuses is not reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _default_vpc_and_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return vpc_id, subnets[0]["SubnetId"]


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(20):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise



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
