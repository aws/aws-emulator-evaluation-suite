"""update-asg-vpc-zone-identifier-replaces-rather-than-merges."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-asg-vpc-zone-identifier-replaces-rather-than-merges"
GROUP = "representation"
SERVICES = ["autoscaling", "ec2", "ssm"]


def _ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup's VPCZoneIdentifier replaces the group's subnets wholesale: a
    subnet left out of the new value is dropped, not kept alongside the new one."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    net = ctx.network()
    subnet_ids = net.subnet_ids
    assert len(subnet_ids) >= 3, (
        f"the shared network needs 3 subnets for this check, has {len(subnet_ids)}: {subnet_ids!r}"
    )
    by_subnet = {sid: az for az, sid in net.subnets.items()}
    first_pair = subnet_ids[:2]
    third = subnet_ids[2]

    lt_name = ctx.unique_name("sim2real-behav-asg-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _ami(ctx), "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    name = ctx.unique_name("sim2real-behav-asg-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=",".join(first_pair),
    )
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )

    before = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    before_zones = set(before["AvailabilityZones"])
    expected_before = {by_subnet[s] for s in first_pair}
    assert before_zones == expected_before, (
        f"freshly created group has zones {sorted(before_zones)!r}, expected {sorted(expected_before)!r}"
    )

    as_.update_auto_scaling_group(AutoScalingGroupName=name, VPCZoneIdentifier=third)

    after = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    after_zones = set(after["AvailabilityZones"])
    expected_after = {by_subnet[third]}
    assert after_zones == expected_after, (
        f"updating VPCZoneIdentifier to one subnet left zones {sorted(after_zones)!r}, "
        f"expected only {sorted(expected_after)!r} — the old subnets' zones must not survive"
    )
    assert after["VPCZoneIdentifier"] == third, (
        f"expected VPCZoneIdentifier {third!r} after the update, got {after['VPCZoneIdentifier']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
