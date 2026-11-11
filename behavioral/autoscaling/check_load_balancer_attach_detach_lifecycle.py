"""load-balancer-attach-detach-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "load-balancer-attach-detach-lifecycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancers registers a Classic ELB with the group, visible via
    DescribeLoadBalancers; DetachLoadBalancers removes the association again."""
    asg = ctx.client("autoscaling")
    elb = ctx.client("elb")
    subnet = _default_subnet(ctx)

    lb_name = ctx.unique_name("sim2real-b-clb-")
    elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=[subnet["subnet_id"]],
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=lb_name))
    elb.add_tags(LoadBalancerNames=[lb_name], Tags=[{"Key": "sim2real", "Value": CHECK}])

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name, subnet["subnet_id"])

    asg.attach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[lb_name])

    lbs = _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda items: any(lb["LoadBalancerName"] == lb_name for lb in items),
        timeout_s=90,
        interval_s=3,
    )
    assert any(lb["LoadBalancerName"] == lb_name for lb in lbs), (
        f"load balancer not visible via DescribeLoadBalancers after attach: {lbs}"
    )

    asg.detach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[lb_name])

    lbs_after = _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda items: not any(lb["LoadBalancerName"] == lb_name for lb in items),
        timeout_s=90,
        interval_s=3,
    )
    assert not any(lb["LoadBalancerName"] == lb_name for lb in lbs_after), (
        f"load balancer still present via DescribeLoadBalancers after detach: {lbs_after}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(
            f"condition not met within {timeout_s}s; last observed value: {result!r}"
        )
    return result


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
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
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
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
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
