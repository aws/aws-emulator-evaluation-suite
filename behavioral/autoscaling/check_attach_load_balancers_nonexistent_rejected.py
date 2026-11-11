"""attach-load-balancers-nonexistent-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "attach-load-balancers-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancers is rejected with ValidationError when the named Classic Load
    Balancer does not exist, and the group's load balancer set stays empty; the same group
    successfully attaches a real Classic Load Balancer (positive control)."""
    autoscaling = ctx.client("autoscaling")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx, count=1)
    sg_id = _default_security_group(ctx, vpc_id)

    lt_id = _create_launch_template(ctx)
    group = _create_asg(ctx, lt_id, subnet_ids)

    bogus_name = ctx.unique_name("sim2real-missing-clb-")[:32]
    code, message = _client_error(
        lambda: autoscaling.attach_load_balancers(
            AutoScalingGroupName=group, LoadBalancerNames=[bogus_name]
        )
    )
    assert code == "ValidationError", f"expected ValidationError attaching a nonexistent CLB, got {code}"
    assert message == "Provided Load Balancers may not be valid. Please ensure they exist and try again.", f"expected the exact refusal message, got {message!r}"

    unaffected = autoscaling.describe_load_balancers(AutoScalingGroupName=group)["LoadBalancers"]
    assert unaffected == [], f"group should have no load balancers after the rejected attach, got {unaffected}"

    # Positive control: attaching a real Classic Load Balancer with the same call shape succeeds.
    real_lb_name = _create_classic_lb(ctx, subnet_ids, sg_id)
    autoscaling.attach_load_balancers(AutoScalingGroupName=group, LoadBalancerNames=[real_lb_name])
    attached = _poll_until(
        lambda: autoscaling.describe_load_balancers(AutoScalingGroupName=group)["LoadBalancers"],
        lambda lbs: len(lbs) == 1,
        timeout_s=90,
        interval_s=3,
        description=f"real CLB {real_lb_name!r} attaching to group {group!r}",
    )
    assert len(attached) == 1 and attached[0]["LoadBalancerName"] == real_lb_name, (
        f"expected exactly one attached load balancer named {real_lb_name!r}, got {attached!r}"
    )


import time
from botocore.exceptions import ClientError


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {result!r}")


def _default_vpc_and_subnets(ctx, count: int = 1) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:

        raise AssertionError("no network subnets in the shared network")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _default_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:

        raise AssertionError("no default security group in the shared network")
    return sgs[0]["GroupId"]


_MANAGED_TAG_KEY = "sim2real:managed"


def _create_classic_lb(ctx, subnet_ids: list[str], sg_id: str) -> str:
    elb = ctx.client("elb")
    name = ctx.unique_name("sim2real-clb-")[-32:]
    elb.create_load_balancer(
        LoadBalancerName=name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=name))
    elb.add_tags(LoadBalancerNames=[name], Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}])
    return name


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(
    ctx,
    launch_template_id: str,
    subnet_ids: list[str],
    min_size: int = 0,
    max_size: int = 0,
    desired: int = 0,
    extra: dict[str, Any] | None = None,
) -> str:
    autoscaling = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-behav-asg-")
    kwargs: dict[str, Any] = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": launch_template_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true", "PropagateAtLaunch": True}],
    )
    if extra:
        kwargs.update(extra)
    autoscaling.create_auto_scaling_group(**kwargs)
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
