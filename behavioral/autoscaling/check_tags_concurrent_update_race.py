"""tags-concurrent-update-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-concurrent-update-race"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateOrUpdateTags and DeleteTags racing on the same tag key must resolve
    to a single, stable final state: DescribeTags never reports duplicate entries for the key
    and never oscillates between reads once the race has settled."""
    asg = ctx.client("autoscaling")
    lt_name = _create_launch_template(ctx, ami_id=_get_al2_ami(ctx))
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[ctx.network().availability_zones[0]],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    tag_key = "sim2real-race-tag"

    def _put():
        try:
            asg.create_or_update_tags(
                Tags=[
                    {
                        "ResourceId": group_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": tag_key,
                        "Value": "present",
                        "PropagateAtLaunch": False,
                    }
                ]
            )
        except ClientError:
            pass

    def _delete():
        try:
            asg.delete_tags(
                Tags=[
                    {
                        "ResourceId": group_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": tag_key,
                        "Value": "present",
                        "PropagateAtLaunch": False,
                    }
                ]
            )
        except ClientError:
            pass

    def _matching_tag_count() -> int:
        tags = asg.describe_tags(
            Filters=[
                {"Name": "auto-scaling-group", "Values": [group_name]},
                {"Name": "key", "Values": [tag_key]},
            ]
        )["Tags"]
        return len(tags)

    # Seed the tag so the concurrent DeleteTags calls have something to race against. This call is
    # NOT allowed to swallow its error: if CreateOrUpdateTags is broken (denied, malformed, silently
    # a no-op), every _put in the race below would fail the same way and the tag count would sit at
    # a stable 0 throughout -- which the race assertions below would then mistake for "the race
    # settled cleanly" instead of "nothing ever worked". This is the positive control.
    asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": tag_key,
                "Value": "present",
                "PropagateAtLaunch": False,
            }
        ]
    )
    assert _matching_tag_count() == 1, (
        "positive control failed: CreateOrUpdateTags did not produce a tag readable via "
        "DescribeTags before the race started"
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_put if i % 2 == 0 else _delete) for i in range(8)]
        for f in futures:
            f.result()

    snapshots = []
    for _ in range(5):
        snapshots.append(_matching_tag_count())
        time.sleep(1)

    assert all(c == snapshots[0] for c in snapshots), (
        f"tag state oscillated across repeated reads after the race settled: {snapshots}"
    )
    assert snapshots[0] in (0, 1), (
        f"expected exactly 0 or 1 matching tag entries after the race, found "
        f"{snapshots[0]} -- indicates duplicate/corrupted tag storage"
    )


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
