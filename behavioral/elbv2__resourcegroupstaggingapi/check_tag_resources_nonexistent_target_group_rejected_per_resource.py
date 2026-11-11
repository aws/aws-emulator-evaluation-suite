"""tag-resources-nonexistent-target-group-rejected-per-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-target-group-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["elbv2", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch naming one live target group and one valid but never-created target
    group ARN returns 200, tags the live one, and reports the absent one in FailedResourcesMap with
    elbv2's TargetGroupNotFound -- never silently accepted and never a whole-batch failure.
    """
    elbv2 = ctx.client("elbv2")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")
    ec2 = ctx.client("ec2")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    # The check's own VPC: a target group needs only a VpcId, so no subnet or gateway is minted.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc",
                            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgvpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    name = ctx.unique_name("sim2real-behav-tg-")
    live_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=live_arn))

    # elbv2 target-group names are capped at 32 characters, so the ghost name must stay short
    # even though it still needs to be unique.
    ghost_name = ctx.unique_name("sim2real-ghost-")
    ghost_arn = f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:targetgroup/{ghost_name}/0123456789abcdef"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent target "
        f"group {ghost_arn!r} -- the live target group {live_arn!r} must not fail and the "
        f"absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "TargetGroupNotFound", (
        f"the per-resource ErrorCode for an absent target group was {detail['ErrorCode']!r}, "
        f"expected elbv2's own TargetGroupNotFound"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected_message = f"Target groups '{ghost_arn}' not found"
    assert detail["ErrorMessage"] == expected_message, (
        f"the per-resource ErrorMessage for an absent target group was {detail['ErrorMessage']!r}, "
        f"expected {expected_message!r}"
    )

    described = _poll_until(
        lambda: elbv2.describe_tags(ResourceArns=[live_arn])["TagDescriptions"][0]["Tags"],
        lambda tag_list: {t["Key"]: t["Value"] for t in tag_list}.get(key) == "partial",
        timeout_s=180.0,
    )
    tag_map = {t["Key"]: t["Value"] for t in described}
    assert tag_map.get(key) == "partial", (
        f"the live target group {live_arn!r} never received {key}=partial (saw {tag_map!r}) "
        f"-- a partial failure must still apply the tags that succeeded"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
