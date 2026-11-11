"""search-resources-tag-filter-matches-tagged-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "search-resources-tag-filter-matches-tagged-resource"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchResources with a TAG_FILTERS_1_0 query finds a real tagged SQS queue (eventually)."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    qname = ctx.unique_name("sim2real-rg-sqs-")
    url = sqs.create_queue(QueueName=qname, tags={"sim2real-rg-marker": qname})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {
                "ResourceTypeFilters": ["AWS::SQS::Queue"],
                "TagFilters": [{"Key": "sim2real-rg-marker", "Values": [qname]}],
            }
        ),
    }

    def probe():
        return rg.search_resources(ResourceQuery=query)["ResourceIdentifiers"]

    matches = _poll_until(
        probe, lambda ids: any(r["ResourceArn"] == arn for r in ids), timeout_s=240.0, interval_s=15.0
    )
    found = [r for r in matches if r["ResourceArn"] == arn]
    if not found:
        raise AssertionError(f"queue {arn} never appeared in SearchResources results within timeout")
    assert found[0]["ResourceType"] == "AWS::SQS::Queue", (
        f"expected ResourceType 'AWS::SQS::Queue' for {arn}, got {found[0]['ResourceType']!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
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
