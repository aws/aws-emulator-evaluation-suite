"""group-resources-query-based-group-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "group-resources-query-based-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-groups"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GroupResources is rejected for a TAG_FILTERS_1_0 query-based group; membership stays
    untouched, and the group's own ResourceQuery is unaffected by the rejected call."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    qname = ctx.unique_name("sim2real-rg-grqb-")
    url = sqs.create_queue(QueueName=qname)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    tag_group = ctx.unique_name("sim2real-rg-grqb-tag-")
    tag_query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {"ResourceTypeFilters": ["AWS::AllSupported"], "TagFilters": [{"Key": "marker", "Values": ["nomatch"]}]}
        ),
    }
    rg.create_group(Name=tag_group, ResourceQuery=tag_query)
    ctx.on_cleanup(lambda: rg.delete_group(Group=tag_group))

    code_tag, message_tag = _client_error(
        lambda: rg.group_resources(Group=tag_group, ResourceArns=[arn]), expect="BadRequestException"
    )
    assert code_tag == "BadRequestException", f"expected BadRequestException, got {code_tag!r}"
    assert message_tag == "This operation does not support the target", (
        f"GroupResources on a query-based group returned message {message_tag!r}"
    )
    members_tag = {i["Identifier"]["ResourceArn"] for i in rg.list_group_resources(Group=tag_group)["Resources"]}
    assert arn not in members_tag, f"rejected GroupResources call still added {arn} to {tag_group}"

    # Positive control (config leg): the rejection is specific to query-based groups -- the
    # group's own ResourceQuery is unaffected by the rejected call.
    gq = rg.get_group_query(Group=tag_group)["GroupQuery"]["ResourceQuery"]
    assert gq["Type"] == "TAG_FILTERS_1_0", f"tag_group query type changed to {gq['Type']!r}"


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
