"""tag-filter-finds-resources-across-two-services."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-filter-finds-resources-across-two-services"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One TagResources call over two different services' ARNs becomes one queryable index entry
    per resource, and a tag filter returns exactly those two.
    """
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    rgt = ctx.client("resourcegroupstaggingapi")

    # A key only this run uses, so every assertion below is a property of the QUERY rather than
    # of whatever else happens to live in this shared account.
    key = ctx.unique_name("sim2real-behav-xsvc-")
    value = ctx.unique_name("sim2real-behav-v-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    t_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-t-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=t_arn))

    tagged = rgt.tag_resources(ResourceARNList=[q_arn, t_arn], Tags={key: value})
    # Untag both keys back off even though the resources are deleted below: the index entry is
    # what this check created, and a deleted resource's key can linger in the account's tag-key
    # summary until the index catches up.
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn, t_arn], TagKeys=[key]))
    assert tagged["FailedResourcesMap"] == {}, (
        f"tagging a live queue and topic reported per-resource failures: {tagged['FailedResourcesMap']!r}"
    )

    found = _poll_until(
        lambda: _all_resources(rgt, TagFilters=[{"Key": key, "Values": [value]}]),
        lambda mappings: {m["ResourceARN"] for m in mappings} == {q_arn, t_arn},
        timeout_s=180.0,
    )
    arns = {m["ResourceARN"] for m in found}
    assert arns == {q_arn, t_arn}, (
        f"tag filter {key}={value} returned {sorted(arns)!r}, expected exactly the queue "
        f"{q_arn!r} and the topic {t_arn!r}"
    )

    # The mapping must carry back the tag that matched, not merely the ARN.
    for mapping in found:
        pairs = {t["Key"]: t["Value"] for t in mapping["Tags"]}
        assert pairs.get(key) == value, (
            f"{mapping['ResourceARN']!r} came back with tags {pairs!r}, which does not carry "
            f"{key}={value}"
        )

    # Same key, a value nothing was tagged with: the filter must discriminate on VALUE, not just
    # on the presence of the key. Scoped to our own key, so 'empty' is a property of the query.
    other = _all_resources(rgt, TagFilters=[{"Key": key, "Values": [value + "-absent"]}])
    assert other == [], (
        f"tag filter {key}={value}-absent matched {[m['ResourceARN'] for m in other]!r}; no "
        f"resource carries that value"
    )


# ===== helpers (self-contained) =====
def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end.

    The account may be shared, so a single page is never the whole answer even under a filter.
    """
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
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
