"""list-group-resources-type-filter-mismatch-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-group-resources-type-filter-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListGroupResources rejects a resource-type filter absent from the group's own query,
    while a filter that IS part of the query is accepted and actually reflects membership."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    qname = ctx.unique_name("sim2real-rg-typemismatch-")
    qurl = sqs.create_queue(QueueName=qname, tags={"marker": qname})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=qurl))
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    group_name = ctx.unique_name("sim2real-rg-typemismatch-group-")
    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {"ResourceTypeFilters": ["AWS::SQS::Queue"], "TagFilters": [{"Key": "marker", "Values": [qname]}]}
        ),
    }
    rg.create_group(Name=group_name, ResourceQuery=query)
    ctx.on_cleanup(lambda: rg.delete_group(Group=group_name))

    code, message = _client_error(
        lambda: rg.list_group_resources(
            Group=group_name, Filters=[{"Name": "resource-type", "Values": ["AWS::EC2::Instance"]}]
        ),
        expect="BadRequestException",
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for a resource-type filter absent from the group's own "
        f"query, got {code}"
    )
    assert message == (
        "Filters not valid: The resource types specified as filters in the request are incompatible "
        "with the group query: AWS::EC2::Instance"
    ), f"ListGroupResources with a mismatched type filter returned message {message!r}"

    # Positive control: filtering by a type that IS part of the group's own query is accepted
    # AND reflects real membership -- not merely "did not raise".
    def probe():
        return rg.list_group_resources(
            Group=group_name, Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}]
        )["Resources"]

    resources = _poll_until(
        probe, lambda items: any(i["Identifier"]["ResourceArn"] == qarn for i in items), timeout_s=240.0, interval_s=15.0
    )
    matched = [i for i in resources if i["Identifier"]["ResourceArn"] == qarn]
    if not matched:
        raise AssertionError(f"queue {qarn} never appeared in the type-filtered ListGroupResources for {group_name}")
    assert matched[0]["Identifier"]["ResourceType"] == "AWS::SQS::Queue", (
        f"expected ResourceType AWS::SQS::Queue for {qarn}, got {matched[0]['Identifier']['ResourceType']}"
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


def _client_error(fn, *, expect):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {expect} but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
