"""attach-load-balancer-during-group-deletion-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-load-balancer-during-group-deletion-blocked"
GROUP = "negative-classes"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancers on a fully deleted Auto Scaling group is rejected with ValidationError
    "AutoScalingGroup name not found - null", while the same call on an existing group succeeds."""
    ec2 = ctx.client("ec2")
    elb = ctx.client("elb")
    autoscaling = ctx.client("autoscaling")

    subnet_id = _default_subnet(ctx)
    if subnet_id is None:
        raise AssertionError(
            "no default VPC/subnet available in this account/region to host a Classic ELB; "
            "would need an explicit VPC+subnet fixture to close this gap"
        )

    lb_name = ctx.unique_name("sim2real-lb-")[:32].rstrip("-")
    elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=[subnet_id],
        Tags=[{"Key": "sim2real-behav", "Value": lb_name}],
    )
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerName=lb_name))

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": lt_name}]}
        ],
    )
    lt_id = lt["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    healthy_asg = ctx.unique_name("sim2real-behav-asg-healthy-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=healthy_asg,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {
                "ResourceId": healthy_asg,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-behav",
                "Value": healthy_asg,
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=healthy_asg, ForceDelete=True)
    )

    autoscaling.attach_load_balancers(AutoScalingGroupName=healthy_asg, LoadBalancerNames=[lb_name])
    attached = autoscaling.describe_load_balancers(AutoScalingGroupName=healthy_asg)["LoadBalancers"]
    assert any(lb["LoadBalancerName"] == lb_name for lb in attached), (
        f"expected {lb_name!r} attached to healthy group {healthy_asg!r} via an independent "
        f"DescribeLoadBalancers read, got {attached!r}"
    )

    # Wait until the group is fully gone: AWS accepts the attach while deletion is in progress.
    deleted_asg = ctx.unique_name("sim2real-behav-asg-deleted-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=deleted_asg,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {
                "ResourceId": deleted_asg,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-behav",
                "Value": deleted_asg,
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(lambda: _delete_group_if_present(autoscaling, deleted_asg))
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=deleted_asg)
    _wait_for_gone(ctx, autoscaling, deleted_asg)

    code, message = _client_error(
        lambda: autoscaling.attach_load_balancers(
            AutoScalingGroupName=deleted_asg, LoadBalancerNames=[lb_name]
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "AutoScalingGroup name not found - null", f"expected the exact refusal message, got {message!r}"

    still_gone = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[deleted_asg])[
        "AutoScalingGroups"
    ]
    assert still_gone == [], (
        f"expected {deleted_asg!r} to remain absent after the rejected attach, "
        f"got {still_gone!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. Success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None
    return subnets[0]["SubnetId"]


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _delete_group_if_present(autoscaling, name):
    """Force-delete the group; only its "not found" ValidationError means it is already gone."""
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


def _wait_for_gone(ctx, autoscaling, asg_name, timeout=120, interval=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ]
        if not groups:
            return
        time.sleep(interval)
    raise AssertionError(f"{asg_name} was not fully deleted within {timeout}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

