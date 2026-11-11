"""untag-removes-resource-from-tag-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "untag-removes-resource-from-tag-query"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UntagResources removes exactly one (resource, key) pair from the index: the other resource
    keeps the key and the untagged resource keeps its other key.
    """
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    rgt = ctx.client("resourcegroupstaggingapi")

    shared = ctx.unique_name("sim2real-behav-shared-")
    kept = ctx.unique_name("sim2real-behav-kept-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    t_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-t-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=t_arn))

    rgt.tag_resources(ResourceARNList=[q_arn, t_arn], Tags={shared: "on-both"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[q_arn, t_arn], TagKeys=[shared]))
    rgt.tag_resources(ResourceARNList=[t_arn], Tags={kept: "topic-only"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[t_arn], TagKeys=[kept]))

    before = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": shared}])},
        lambda arns: arns == {q_arn, t_arn},
        timeout_s=180.0,
    )
    assert before == {q_arn, t_arn}, (
        f"before the untag, {shared!r} matched {sorted(before)!r}, expected the queue and the topic"
    )

    removed = rgt.untag_resources(ResourceARNList=[t_arn], TagKeys=[shared])
    assert removed["FailedResourcesMap"] == {}, (
        f"untagging a live topic reported per-resource failures: {removed['FailedResourcesMap']!r}"
    )

    after = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": shared}])},
        lambda arns: arns == {q_arn},
        timeout_s=180.0,
    )
    assert after == {q_arn}, (
        f"after untagging only {t_arn!r}, {shared!r} matched {sorted(after)!r}, expected exactly "
        f"the queue {q_arn!r} — the untag must be scoped to the ARN it named"
    )

    # The topic's OTHER key is untouched: untagging one key is not untagging the resource.
    survivors = _all_resources(rgt, TagFilters=[{"Key": kept}])
    survivor_arns = {m["ResourceARN"] for m in survivors}
    assert survivor_arns == {t_arn}, (
        f"after the untag, {kept!r} matched {sorted(survivor_arns)!r}, expected exactly the topic "
        f"{t_arn!r} — removing {shared!r} must not remove the topic's other tags"
    )
    topic_tags = {t["Key"]: t["Value"] for t in survivors[0]["Tags"]}
    assert topic_tags == {kept: "topic-only"}, (
        f"the topic's tag set is {topic_tags!r}; expected only {kept}=topic-only to remain"
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
