"""tag-delete-survivor-in-describe-asg-and-describe-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-delete-survivor-in-describe-asg-and-describe-tags"
GROUP = "tags"
SERVICES = ["autoscaling"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _resolve_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]


def _resolve_subnet(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _create_zero_capacity_group(ctx, asg, group_name, tag_list) -> None:
    """Create a zero-capacity (Min/Max/Desired all 0) Auto Scaling group carrying tag_list."""
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-tagsurvivor-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _resolve_ami(ctx), "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=_resolve_subnet(ctx),
        Tags=tag_list,
    )
    ctx.on_cleanup(
        lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
    )


def _tags_via_describe_tags(asg, group_name) -> dict:
    found = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    return {t["Key"]: t for t in found}


def _tags_via_describe_groups(asg, group_name) -> dict:
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1, f"expected exactly one group named {group_name!r}, got {len(groups)}"
    return {t["Key"]: t for t in groups[0]["Tags"]}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTags removing one of two tags on a zero-capacity group leaves only the other tag, with
    its value and PropagateAtLaunch, visible through both DescribeTags and DescribeAutoScalingGroups;
    repeating the same DeleteTags call answers 200 and leaves the survivor untouched.
    """
    asg = ctx.client("autoscaling")
    group_name = ctx.unique_name("sim2real-behav-tagsurvivor-grp-")
    key_removed = "environment"
    key_kept = "cost-center"
    tag_removed = {
        "ResourceId": group_name,
        "ResourceType": "auto-scaling-group",
        "Key": key_removed,
        "Value": "staging",
        "PropagateAtLaunch": True,
    }
    tag_kept = {
        "ResourceId": group_name,
        "ResourceType": "auto-scaling-group",
        "Key": key_kept,
        "Value": "finance",
        "PropagateAtLaunch": False,
    }
    _create_zero_capacity_group(ctx, asg, group_name, [tag_removed, tag_kept])

    by_tags_api = _tags_via_describe_tags(asg, group_name)
    assert set(by_tags_api) == {key_removed, key_kept}, (
        f"expected both tags after create via DescribeTags, got {sorted(by_tags_api)}"
    )
    by_group_api = _tags_via_describe_groups(asg, group_name)
    assert set(by_group_api) == {key_removed, key_kept}, (
        f"expected both tags after create via DescribeAutoScalingGroups, got {sorted(by_group_api)}"
    )

    # --- delete the one key, naming only Key (no Value) ---
    first_delete = asg.delete_tags(
        Tags=[{"ResourceId": group_name, "ResourceType": "auto-scaling-group", "Key": key_removed}]
    )
    first_status = first_delete["ResponseMetadata"]["HTTPStatusCode"]
    assert first_status == 200, f"expected HTTP 200 deleting {key_removed!r}, got {first_status}"

    by_tags_api = _tags_via_describe_tags(asg, group_name)
    assert set(by_tags_api) == {key_kept}, (
        f"DescribeTags expected only {key_kept!r} to remain, got {sorted(by_tags_api)}"
    )
    survivor = by_tags_api[key_kept]
    assert survivor["Value"] == "finance" and survivor["PropagateAtLaunch"] is False, survivor

    by_group_api = _tags_via_describe_groups(asg, group_name)
    assert set(by_group_api) == {key_kept}, (
        f"DescribeAutoScalingGroups.Tags expected only {key_kept!r} to remain, got {sorted(by_group_api)}"
    )
    survivor = by_group_api[key_kept]
    assert survivor["Value"] == "finance" and survivor["PropagateAtLaunch"] is False, survivor

    # --- deleting the same, already-removed key a second time is idempotent ---
    second_delete = asg.delete_tags(
        Tags=[{"ResourceId": group_name, "ResourceType": "auto-scaling-group", "Key": key_removed}]
    )
    second_status = second_delete["ResponseMetadata"]["HTTPStatusCode"]
    assert second_status == 200, (
        f"expected HTTP 200 deleting the already-removed {key_removed!r} again, got {second_status}"
    )

    by_tags_api = _tags_via_describe_tags(asg, group_name)
    assert set(by_tags_api) == {key_kept}, (
        f"repeating DeleteTags for {key_removed!r} must leave {key_kept!r} alone, got {sorted(by_tags_api)}"
    )
    by_group_api = _tags_via_describe_groups(asg, group_name)
    assert set(by_group_api) == {key_kept}, (
        f"repeating DeleteTags for {key_removed!r} must leave DescribeAutoScalingGroups.Tags alone, "
        f"got {sorted(by_group_api)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
