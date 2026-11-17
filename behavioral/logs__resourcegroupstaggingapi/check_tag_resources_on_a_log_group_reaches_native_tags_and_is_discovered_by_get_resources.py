"""tag-resources-on-a-log-group-reaches-native-tags-and-is-discovered-by-get-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-on-a-log-group-reaches-native-tags-and-is-discovered-by-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["logs", "resourcegroupstaggingapi"]


def _poll_until(observe, satisfied, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        value = observe()
        if satisfied(value):
            return value
        if time.monotonic() > deadline:
            return value
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResources on a log group's non-wildcard ARN reaches ListTagsForResource and makes the
    group discoverable by GetResources; UntagResources removes it from both.
    """
    logs = ctx.client("logs")
    rgt = ctx.client("resourcegroupstaggingapi")

    group_name = ctx.unique_name("/sim2real/behav-tag-reach-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    # The ARN DescribeLogGroups returns carries a trailing ":*"; TagResource, UntagResource and
    # ListTagsForResource take the log group's ARN without it.
    full_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    assert full_arn.endswith(":*"), f"describe_log_groups returned {full_arn!r}, expected a trailing ':*'"
    group_arn = full_arn[:-2]

    key = ctx.unique_name("sim2real-behav-tagkey-")
    value = ctx.unique_name("sim2real-behav-tagval-")

    failed = rgt.tag_resources(ResourceARNList=[group_arn], Tags={key: value})["FailedResourcesMap"]
    assert failed == {}, f"TagResources on a freshly created log group failed: {failed!r}"

    native = logs.list_tags_for_resource(resourceArn=group_arn).get("tags", {})
    assert native == {key: value}, (
        f"ListTagsForResource (a different operation than TagResources) returned {native!r}, "
        f"expected {{{key!r}: {value!r}}}"
    )

    mappings = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": key, "Values": [value]}],
            ResourceTypeFilters=["logs:log-group"],
        )["ResourceTagMappingList"],
        lambda m: len(m) > 0,
        timeout_s=60.0,
    )
    found = [m for m in mappings if m["ResourceARN"] == group_arn]
    assert len(found) == 1, (
        f"GetResources filtered on {key!r}={value!r} returned {mappings!r}, expected exactly "
        f"one mapping for {group_arn!r}"
    )
    found_tags = {t["Key"]: t["Value"] for t in found[0]["Tags"]}
    assert found_tags[key] == value, (
        f"GetResources reported Tags={found[0]['Tags']!r} for {group_arn!r}, expected {key!r}={value!r}"
    )

    rgt.untag_resources(ResourceARNList=[group_arn], TagKeys=[key])

    native_after = logs.list_tags_for_resource(resourceArn=group_arn).get("tags", {})
    assert key not in native_after, (
        f"ListTagsForResource still reports {key!r} after UntagResources: {native_after!r}"
    )

    remaining = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": key, "Values": [value]}],
            ResourceTypeFilters=["logs:log-group"],
        )["ResourceTagMappingList"],
        lambda m: len(m) == 0,
        timeout_s=60.0,
    )
    assert remaining == [], (
        f"GetResources still discovers {group_arn!r} under {key!r}={value!r} after UntagResources: "
        f"{remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
