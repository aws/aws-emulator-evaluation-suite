"""stack-tag-removal-propagates-to-queue-without-replacement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stack-tag-removal-propagates-to-queue-without-replacement"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(queue_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
        },
    })


def _wait_terminal(cf, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks every interval_s until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended in {status!r}, expected DELETE_COMPLETE")


def _ordered_decisive_events(cf, stack_id: str) -> list:
    """Chronological (LogicalResourceId, ResourceStatus) pairs, terminal statuses only."""
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    events = [e for page in pages for e in page["StackEvents"]]
    events.reverse()
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if e["ResourceStatus"] in _TERMINAL
    ]


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Dropping one stack-level Tag on UpdateStack removes it from a taggable queue (SQS's own
    ListQueueTags) while leaving an untouched tag, and the queue is updated in place: its
    service-minted CreatedTimestamp survives the update.
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-behav-sqstag-")
    queue_name = ctx.unique_name("sim2real-behav-sqstag-q-")
    template = _template(queue_name)

    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[
            {"Key": "sim2real-keep", "Value": "1"},
            {"Key": "sim2real-drop", "Value": "2"},
        ],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, stack_id))
    status = _wait_terminal(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"setup stack {stack_name!r} ended in {status!r}"

    queue_url = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Queue")[
        "StackResourceDetail"]["PhysicalResourceId"]
    before_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert before_tags == {"sim2real-keep": "1", "sim2real-drop": "2"}, before_tags
    created_before = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["CreatedTimestamp"]
    )["Attributes"]["CreatedTimestamp"]

    cf.update_stack(
        StackName=stack_id,
        TemplateBody=template,
        Tags=[{"Key": "sim2real-keep", "Value": "1"}],
    )
    status = _wait_terminal(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack_name!r} update ended in {status!r}"

    decisive = _ordered_decisive_events(cf, stack_id)
    queue_done = decisive.index(("Queue", "UPDATE_COMPLETE"))
    stack_done = decisive.index((stack_name, "UPDATE_COMPLETE"))
    assert queue_done < stack_done, (
        f"the Queue's own UPDATE_COMPLETE must precede the stack's, got index "
        f"{queue_done} vs {stack_done} in {decisive!r}"
    )

    created_after = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["CreatedTimestamp"]
    )["Attributes"]["CreatedTimestamp"]
    assert created_after == created_before, (
        f"CreatedTimestamp changed from {created_before!r} to {created_after!r}; the queue was "
        f"replaced instead of updated in place"
    )

    after_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert after_tags == {"sim2real-keep": "1"}, (
        f"ListQueueTags on the same queue after removing the stack tag returned {after_tags!r}, "
        f"expected only the tag that was kept"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
