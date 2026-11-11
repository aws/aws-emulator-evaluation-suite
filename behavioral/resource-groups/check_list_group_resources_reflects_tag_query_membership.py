"""list-group-resources-reflects-tag-query-membership."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-group-resources-reflects-tag-query-membership"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query-based group's ListGroupResources eventually includes a matching tagged resource."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    qname = ctx.unique_name("sim2real-rg-lgr-")
    url = sqs.create_queue(QueueName=qname, tags={"sim2real-rg-marker": qname})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    group_name = ctx.unique_name("sim2real-rg-lgrgroup-")
    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {
                "ResourceTypeFilters": ["AWS::SQS::Queue"],
                "TagFilters": [{"Key": "sim2real-rg-marker", "Values": [qname]}],
            }
        ),
    }
    rg.create_group(Name=group_name, ResourceQuery=query)
    ctx.on_cleanup(lambda: rg.delete_group(Group=group_name))

    def probe():
        return rg.list_group_resources(Group=group_name)["Resources"]

    resources = _poll_until(
        probe,
        lambda items: any(i["Identifier"]["ResourceArn"] == arn for i in items),
        timeout_s=240.0,
        interval_s=15.0,
    )
    matched = [i for i in resources if i["Identifier"]["ResourceArn"] == arn]
    if not matched:
        raise AssertionError(f"queue {arn} never appeared in ListGroupResources for {group_name}")
    actual_type = matched[0]["Identifier"]["ResourceType"]
    assert actual_type == "AWS::SQS::Queue", f"expected ResourceType AWS::SQS::Queue, got {actual_type}"


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
