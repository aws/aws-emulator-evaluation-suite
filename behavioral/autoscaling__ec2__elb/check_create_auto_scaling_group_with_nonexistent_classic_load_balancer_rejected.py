"""create-auto-scaling-group-with-nonexistent-classic-load-balancer-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-auto-scaling-group-with-nonexistent-classic-load-balancer-rejected"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _latest_al2023_ami(ctx: Any) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """CreateAutoScalingGroup's LoadBalancerNames rejects a name with no matching Classic Load
    Balancer and creates nothing; the identical create naming a real one succeeds, and the
    Classic Load Balancer's own describe confirms it exists."""
    ec2 = ctx.client("ec2")
    elb = ctx.client("elb")
    autoscaling = ctx.client("autoscaling")

    vpc_id = ctx.network().vpc_id
    subnet_id = ctx.network().subnet_ids[0]

    lt_id = ec2.create_launch_template(
        LaunchTemplateName=ctx.unique_name("sim2real-clbreject-lt-"),
        LaunchTemplateData={"ImageId": _latest_al2023_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template",
                             "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    bogus_name = ctx.unique_name("sim2real-absent-clb-")[-32:]
    group_name = ctx.unique_name("sim2real-clbreject-asg-")
    code, message = _error(lambda: autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        LoadBalancerNames=[bogus_name],
    ))
    assert code == "ValidationError", (
        f"creating a group with a nonexistent Classic Load Balancer returned {code!r}, "
        f"expected ValidationError"
    )
    assert message == (
        "Provided Load Balancers may not be valid. Please ensure they exist and try again."
    ), f"unexpected refusal message: {message!r}"

    rejected = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert rejected == [], f"the rejected create left behind a group: {rejected!r}"

    # Positive control: the identical create naming a real, existing Classic Load Balancer
    # succeeds, and the load balancer's own describe is what confirms it is real.
    real_lb_name = ctx.unique_name("sim2real-clbreject-clb-")[-32:]
    elb.create_load_balancer(
        LoadBalancerName=real_lb_name,
        Listeners=[{"Protocol": "TCP", "LoadBalancerPort": 80, "InstanceProtocol": "TCP", "InstancePort": 80}],
        Subnets=[subnet_id],
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=real_lb_name))
    described = elb.describe_load_balancers(LoadBalancerNames=[real_lb_name])["LoadBalancerDescriptions"]
    assert len(described) == 1 and described[0]["LoadBalancerName"] == real_lb_name, (
        f"expected the load balancer's own describe to list exactly {real_lb_name!r}, got {described!r}"
    )
    assert described[0]["VPCId"] == vpc_id, (
        f"expected the load balancer to sit in {vpc_id!r}, got {described[0].get('VPCId')!r}"
    )

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        LoadBalancerNames=[real_lb_name],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=group_name, ForceDelete=True))
    accepted = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert len(accepted) == 1 and accepted[0]["LoadBalancerNames"] == [real_lb_name], (
        f"expected the group to carry exactly {real_lb_name!r}, got {accepted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
