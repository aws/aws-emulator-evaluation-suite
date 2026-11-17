"""get-resources-tag-filter-matches-an-sns-topic-by-value-not-a-different-one."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-resources-tag-filter-matches-an-sns-topic-by-value-not-a-different-one"
GROUP = "tag-inventory"
SERVICES = ["resourcegroupstaggingapi", "sns"]


def _get_resources(rgta, key, value, *, budget_s=60.0, poll_s=2.0):
    """ARNs GetResources returns for TagFilters=[{key: [value]}], polled to appear."""
    deadline = time.monotonic() + budget_s
    while True:
        arns = set()
        paginator = rgta.get_paginator("get_resources")
        for page in paginator.paginate(TagFilters=[{"Key": key, "Values": [value]}]):
            arns.update(m["ResourceARN"] for m in page["ResourceTagMappingList"])
        if arns or time.monotonic() > deadline:
            return arns
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources finds an SNS topic by its exact tag value and not by a different one.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-tags.html
    """
    sns = ctx.client("sns")
    rgta = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-xsvc-rgta-key")
    value = ctx.unique_name("sim2real-xsvc-rgta-value")
    name = ctx.unique_name("sim2real-xsvc-rgta-topic")

    topic_arn = sns.create_topic(Name=name, Tags=[{"Key": key, "Value": value}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    matching = _get_resources(rgta, key, value)
    assert topic_arn in matching, (
        f"GetResources with TagFilters key={key!r} value={value!r} returned {sorted(matching)!r}, "
        f"expected to include the topic {topic_arn!r}"
    )

    other_value = ctx.unique_name("sim2real-xsvc-rgta-othervalue")
    mismatched = _get_resources(rgta, key, other_value, budget_s=10.0, poll_s=2.0)
    assert topic_arn not in mismatched, (
        f"GetResources with TagFilters key={key!r} value={other_value!r} (a value the topic was "
        f"never tagged with) returned the topic {topic_arn!r} among {sorted(mismatched)!r}"
    )

    sns.untag_resource(ResourceArn=topic_arn, TagKeys=[key])
    removed = _get_resources(rgta, key, value, budget_s=60.0, poll_s=2.0)
    assert topic_arn not in removed, (
        f"topic {topic_arn!r} still matched TagFilters key={key!r} value={value!r} "
        f"after UntagResource removed the key"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
