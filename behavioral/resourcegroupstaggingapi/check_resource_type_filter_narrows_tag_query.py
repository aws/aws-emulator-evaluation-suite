"""resource-type-filter-narrows-tag-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resource-type-filter-narrows-tag-query"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ResourceTypeFilters intersects with TagFilters: a bare service token selects every type that
    service owns, a service:type token selects the same resource for a one-type service, and two
    service tokens select the union.
    """
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-rtf-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    t_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-t-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=t_arn))

    rgt.tag_resources(ResourceARNList=[q_arn, t_arn], Tags={key: "typed"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn, t_arn], TagKeys=[key]))

    def by_type(*types):
        return {
            m["ResourceARN"]
            for m in _all_resources(
                rgt, TagFilters=[{"Key": key}], ResourceTypeFilters=list(types)
            )
        }

    # Positive control for the whole query: both resources are in the index under this key before
    # any type filter is asserted, so an absence below is the filter excluding, not a lagging index.
    both = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])},
        lambda arns: arns == {q_arn, t_arn},
        timeout_s=180.0,
    )
    assert both == {q_arn, t_arn}, (
        f"unfiltered tag query for {key!r} returned {sorted(both)!r}, expected the queue and the topic"
    )

    only_sqs = by_type("sqs")
    assert only_sqs == {q_arn}, (
        f"ResourceTypeFilters=['sqs'] returned {sorted(only_sqs)!r}, expected exactly {q_arn!r}"
    )

    only_sns = by_type("sns")
    assert only_sns == {t_arn}, (
        f"ResourceTypeFilters=['sns'] returned {sorted(only_sns)!r}, expected exactly {t_arn!r}"
    )

    # A service:type token must be accepted and must select the same resource as the bare service
    # token does for a service with one taggable type.
    qualified = by_type("sqs:queue")
    assert qualified == {q_arn}, (
        f"ResourceTypeFilters=['sqs:queue'] returned {sorted(qualified)!r}, expected exactly {q_arn!r}"
    )

    # Two service tokens are a union, not an intersection.
    union = by_type("sqs", "sns")
    assert union == {q_arn, t_arn}, (
        f"ResourceTypeFilters=['sqs','sns'] returned {sorted(union)!r}, expected both {q_arn!r} "
        f"and {t_arn!r}"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
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
