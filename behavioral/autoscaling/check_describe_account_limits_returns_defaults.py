"""describe-account-limits-returns-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-account-limits-returns-defaults"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits returns fixed Max* quotas plus a Number* usage counter
    that the service itself maintains and that counts a group once it is created."""
    autoscaling = ctx.client("autoscaling")

    before = autoscaling.describe_account_limits()
    for key in (
        "MaxNumberOfAutoScalingGroups",
        "MaxNumberOfLaunchConfigurations",
        "NumberOfAutoScalingGroups",
        "NumberOfLaunchConfigurations",
    ):
        assert key in before, f"missing {key} in DescribeAccountLimits response"
        assert isinstance(before[key], int), f"{key} is {type(before[key])!r}, expected int"

    # CreateLaunchConfiguration is no longer available in this account ("Use launch
    # templates to create configuration templates for your Auto Scaling groups."), so
    # the service-maintained usage counter is exercised via NumberOfAutoScalingGroups
    # instead of NumberOfLaunchConfigurations.
    asg_name = _create_empty_asg(ctx)

    after = autoscaling.describe_account_limits()

    # The usage counter is account-wide and moves with any other caller's groups, so it is graded
    # on counting the group just created, which DescribeAutoScalingGroups lists; the fixed quotas
    # themselves are unchanged.
    listed = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert [g["AutoScalingGroupName"] for g in listed] == [asg_name], (
        f"expected DescribeAutoScalingGroups to list {asg_name}, got {listed}"
    )
    assert after["NumberOfAutoScalingGroups"] >= 1, (
        f"expected NumberOfAutoScalingGroups to count {asg_name}, got {after['NumberOfAutoScalingGroups']}"
    )
    assert after["MaxNumberOfAutoScalingGroups"] == before["MaxNumberOfAutoScalingGroups"], (
        f"MaxNumberOfAutoScalingGroups changed from {before['MaxNumberOfAutoScalingGroups']} "
        f"to {after['MaxNumberOfAutoScalingGroups']} merely from creating one group"
    )
    assert after["MaxNumberOfLaunchConfigurations"] == before["MaxNumberOfLaunchConfigurations"], (
        f"MaxNumberOfLaunchConfigurations changed from {before['MaxNumberOfLaunchConfigurations']} "
        f"to {after['MaxNumberOfLaunchConfigurations']} merely from creating one group"
    )
    assert after["NumberOfAutoScalingGroups"] <= after["MaxNumberOfAutoScalingGroups"], (
        f"NumberOfAutoScalingGroups {after['NumberOfAutoScalingGroups']} exceeds reported "
        f"MaxNumberOfAutoScalingGroups {after['MaxNumberOfAutoScalingGroups']}"
    )
    assert asg_name, "auto scaling group creation did not return a name"


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")
    return param["Parameter"]["Value"]


def _create_empty_asg(ctx) -> str:
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _get_al2_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real:managed",
                "Value": "true",
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
