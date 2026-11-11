"""attach-detach-load-balancers-state."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "attach-detach-load-balancers-state"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancers adds an LB to the group's tracked set visible in
    DescribeLoadBalancers, and DetachLoadBalancers removes it."""
    asg = ctx.client("autoscaling")
    elb = ctx.client("elb")

    subnet_id, _vpc_id, _az = _default_subnet(ctx)
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
    )
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True))

    lb_name = ctx.unique_name("sim2real-behav-clb-")[:32]
    elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80}],
        Subnets=[subnet_id],
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=lb_name))

    asg.attach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[lb_name])

    attached = _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda lbs: any(lb["LoadBalancerName"] == lb_name for lb in lbs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    tracked = {lb["LoadBalancerName"] for lb in attached}
    assert lb_name in tracked, f"expected {lb_name} tracked after attach, got {tracked!r}"

    asg.detach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[lb_name])

    detached = _poll_until(
        lambda: asg.describe_load_balancers(AutoScalingGroupName=group_name)["LoadBalancers"],
        lambda lbs: lb_name not in {lb["LoadBalancerName"] for lb in lbs},
        timeout_s=60.0,
        interval_s=3.0,
    )
    remaining = {lb["LoadBalancerName"] for lb in detached}
    assert lb_name not in remaining, f"expected {lb_name} untracked after detach, got {remaining!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
