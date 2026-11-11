"""tags-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag Value with multi-byte unicode is stored and returned byte-for-byte via DescribeTags."""
    autoscaling = ctx.client("autoscaling")
    asg_name = _create_asg(ctx)

    unicode_value = "日本語タグ-emoji-😀-Ω≈ç√-Ω\u00e9\u00e8"
    tag_key = "sim2real-unicode-key"
    autoscaling.create_or_update_tags(
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": tag_key,
                "Value": unicode_value,
                "PropagateAtLaunch": False,
            }
        ]
    )

    resp = autoscaling.describe_tags(
        Filters=[
            {"Name": "auto-scaling-group", "Values": [asg_name]},
            {"Name": "key", "Values": [tag_key]},
        ]
    )
    tags = resp["Tags"]
    assert len(tags) == 1, f"expected exactly one matching tag, got {tags!r}"
    assert tags[0]["Value"] == unicode_value, (
        f"unicode tag value drifted: sent {unicode_value!r}, got {tags[0]['Value']!r}"
    )
    assert tags[0]["Key"] == tag_key, f"expected key {tag_key!r}, got {tags[0]['Key']!r}"
    assert tags[0]["ResourceId"] == asg_name, (
        f"expected resource id {asg_name!r}, got {tags[0]['ResourceId']!r}"
    )


def _create_launch_template(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": _valid_ami(ctx), "InstanceType": "t3.micro"},
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _create_asg(ctx, *, min_size=0, max_size=1, desired=0):
    autoscaling = ctx.client("autoscaling")
    lt_id = _create_launch_template(ctx)
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    return asg_name


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
