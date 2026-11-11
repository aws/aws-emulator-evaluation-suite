"""search-resources-no-match-returns-empty."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "search-resources-no-match-returns-empty"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchResources with a tag filter that matches nothing returns an empty list, not an error —
    proven against a positive control that the same query shape finds a real tagged resource, so a
    target that always answers empty cannot pass alongside one that never filters at all."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    marker_key = "sim2real-rg-nomatch-marker"
    qname = ctx.unique_name("sim2real-rg-nomatch-")
    present_value = ctx.unique_name("sim2real-rg-nomatch-present-")
    url = sqs.create_queue(QueueName=qname, tags={marker_key: present_value})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    def search(value):
        query = {
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {
                    "ResourceTypeFilters": ["AWS::AllSupported"],
                    "TagFilters": [{"Key": marker_key, "Values": [value]}],
                }
            ),
        }
        return rg.search_resources(ResourceQuery=query)["ResourceIdentifiers"]

    positive = _poll_until(
        lambda: search(present_value),
        lambda ids: any(r["ResourceArn"] == arn for r in ids),
        timeout_s=240.0,
        interval_s=15.0,
    )
    if not any(r["ResourceArn"] == arn for r in positive):
        raise AssertionError(f"positive control: queue {arn} never appeared in SearchResources for its own tag")

    absent_value = ctx.unique_name("sim2real-rg-nomatch-absent-")
    empty = search(absent_value)
    assert empty == [], f"expected no matches for tag value {absent_value!r}, got {empty}"


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
