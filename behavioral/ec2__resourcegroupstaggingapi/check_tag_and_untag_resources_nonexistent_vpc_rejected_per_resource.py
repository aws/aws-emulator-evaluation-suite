"""tag-and-untag-resources-nonexistent-vpc-rejected-per-resource."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "tag-and-untag-resources-nonexistent-vpc-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources or UntagResources batch of one live and one absent EC2 vpc applies to the
    live one and reports only the absent one in FailedResourcesMap with EC2's own InvalidID --
    a partial failure, never a whole-batch rejection.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-part-")
    value = ctx.unique_name("sim2real-behav-partv-")

    vpc_id = ec2.create_vpc(CidrBlock="10.93.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    live_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    ghost_id = "vpc-" + uuid.uuid4().hex[:17]
    ghost_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{ghost_id}"

    tag_result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: value})
    tag_failed = tag_result["FailedResourcesMap"]
    assert set(tag_failed) == {ghost_arn}, (
        f"TagResources FailedResourcesMap named {sorted(tag_failed)!r}, expected exactly the "
        f"absent vpc {ghost_arn!r} -- the live vpc {live_arn!r} must not fail and the absent "
        f"one must not pass"
    )
    tag_detail = tag_failed[ghost_arn]
    assert tag_detail["ErrorCode"] == "InvalidID", (
        f"the per-resource ErrorCode for an absent vpc was {tag_detail['ErrorCode']!r}, "
        f"expected EC2's own InvalidID"
    )
    assert tag_detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {tag_detail['StatusCode']!r}, expected 400"
    )
    expected_tag_message = f"The ID '{ghost_id}' is not valid"
    assert tag_detail["ErrorMessage"] == expected_tag_message, (
        f"the per-resource ErrorMessage for an absent vpc was {tag_detail['ErrorMessage']!r}, "
        f"expected {expected_tag_message!r}"
    )

    native_tags = _poll_until(
        lambda: {
            t["Key"]: t["Value"]
            for t in ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])[
                "Tags"
            ]
        },
        lambda m: m.get(key) == value,
        timeout_s=180.0,
    )
    assert native_tags.get(key) == value, (
        f"the live vpc {vpc_id!r} never received {key}={value!r} (saw {native_tags!r}) -- a "
        f"partial failure must still apply the tags that succeeded"
    )

    untag_result = rgt.untag_resources(ResourceARNList=[live_arn, ghost_arn], TagKeys=[key])
    untag_failed = untag_result["FailedResourcesMap"]
    assert set(untag_failed) == {ghost_arn}, (
        f"UntagResources FailedResourcesMap named {sorted(untag_failed)!r}, expected exactly the "
        f"absent vpc {ghost_arn!r} -- the live vpc {live_arn!r} must not fail and the absent "
        f"one must not pass"
    )
    untag_detail = untag_failed[ghost_arn]
    assert untag_detail["ErrorCode"] == "InvalidID", (
        f"the per-resource ErrorCode for an absent vpc was {untag_detail['ErrorCode']!r}, "
        f"expected EC2's own InvalidID"
    )
    assert untag_detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {untag_detail['StatusCode']!r}, expected 400"
    )
    expected_untag_message = f"The ID '{ghost_id}' is not valid"
    assert untag_detail["ErrorMessage"] == expected_untag_message, (
        f"the per-resource ErrorMessage for an absent vpc was {untag_detail['ErrorMessage']!r}, "
        f"expected {expected_untag_message!r}"
    )

    after_untag = _poll_until(
        lambda: {
            t["Key"]: t["Value"]
            for t in ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])[
                "Tags"
            ]
        },
        lambda m: key not in m,
        timeout_s=180.0,
    )
    assert key not in after_untag, (
        f"the live vpc {vpc_id!r} still carries {key}={after_untag.get(key)!r} after "
        f"UntagResources -- the live resource in the same partial-failure batch must still "
        f"be untagged"
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
