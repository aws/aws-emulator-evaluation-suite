"""update-group-query-changes-membership."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-group-query-changes-membership"
GROUP = "data-plane"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroupQuery echoes the new query synchronously; membership eventually re-evaluates to
    both admit the newly-matching resource and drop the resource that no longer matches."""
    sqs = ctx.client("sqs")
    rg = ctx.client("resource-groups")

    q1name = ctx.unique_name("sim2real-rg-uq1-")
    url1 = sqs.create_queue(QueueName=q1name, tags={"sim2real-rg-marker": q1name})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url1))
    arn1 = sqs.get_queue_attributes(QueueUrl=url1, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    group_name = ctx.unique_name("sim2real-rg-uqgroup-")

    def make_query(tag_value):
        return {
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {
                    "ResourceTypeFilters": ["AWS::SQS::Queue"],
                    "TagFilters": [{"Key": "sim2real-rg-marker", "Values": [tag_value]}],
                }
            ),
        }

    rg.create_group(Name=group_name, ResourceQuery=make_query(q1name))
    ctx.on_cleanup(lambda: rg.delete_group(Group=group_name))

    def probe_membership(target_arn):
        return rg.list_group_resources(Group=group_name)["Resources"]

    matches = _poll_until(
        lambda: probe_membership(arn1),
        lambda items: any(i["Identifier"]["ResourceArn"] == arn1 for i in items),
        timeout_s=240.0,
        interval_s=15.0,
    )
    if not any(i["Identifier"]["ResourceArn"] == arn1 for i in matches):
        raise AssertionError("initial queue never appeared as a group member before query update")

    q2name = ctx.unique_name("sim2real-rg-uq2-")
    url2 = sqs.create_queue(QueueName=q2name, tags={"sim2real-rg-marker": q2name})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url2))
    arn2 = sqs.get_queue_attributes(QueueUrl=url2, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rg.update_group_query(Group=group_name, ResourceQuery=make_query(q2name))

    # The query change itself is echoed back synchronously via GetGroupQuery.
    gq = rg.get_group_query(Group=group_name)["GroupQuery"]["ResourceQuery"]
    parsed = json.loads(gq["Query"])
    assert parsed["TagFilters"][0]["Values"] == [q2name], (
        f"expected GetGroupQuery to echo the new tag value {q2name!r}, got {parsed['TagFilters'][0]['Values']!r}"
    )

    # Membership re-evaluation is asynchronous; poll until the query change has fully taken
    # effect: the new resource is a member AND the old one, which no longer matches, is not.
    # A target that unions the old and new query (instead of replacing it) would pass a
    # check that only asserted arn2's arrival, so arn1's departure is asserted here too.
    def probe_arns():
        return {i["Identifier"]["ResourceArn"] for i in probe_membership(arn2)}

    final_arns = _poll_until(
        probe_arns,
        lambda arns: arn2 in arns and arn1 not in arns,
        timeout_s=240.0,
        interval_s=15.0,
    )
    if arn2 not in final_arns:
        raise AssertionError(f"queue2 {arn2} never appeared as a group member after UpdateGroupQuery")
    if arn1 in final_arns:
        raise AssertionError(
            f"queue1 {arn1} still a group member after UpdateGroupQuery changed the query away from it "
            "(query replace did not drop stale membership)"
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
