"""explicit-queue-name-collision-rejected-by-the-resource-handler."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "explicit-queue-name-collision-rejected-by-the-resource-handler"
GROUP = "naming"
SERVICES = ["cloudformation", "sqs"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
})
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_terminal(cf, stack_name, timeout_s=300.0):
    """Poll DescribeStacks until a terminal StackStatus; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _queue_template(queue_name, visibility_timeout):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue",
                                 "Properties": {"QueueName": queue_name,
                                                 "VisibilityTimeout": visibility_timeout}}},
    })


def _reason(cf, stack_name, logical_id, status="CREATE_FAILED"):
    events = cf.describe_stack_events(StackName=stack_name)["StackEvents"]
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def _handler_reason(reason):
    """``(message, HandlerErrorCode)`` of a resource-handler failure reason; its RequestToken
    (a fresh id per request) is stripped before comparison."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return m["message"], m["code"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit QueueName colliding with a pre-existing queue of other attributes fails the
    resource handler and rolls back, leaving that queue unchanged; a free name still creates one."""
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    taken_name = ctx.unique_name("sim2real-behav-q-")
    taken_url = sqs.create_queue(QueueName=taken_name, Attributes={"VisibilityTimeout": "45"})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=taken_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))

    bad_stack = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(StackName=bad_stack, TemplateBody=_queue_template(taken_name, 99))
    ctx.on_cleanup(_teardown(lambda: cf.delete_stack(StackName=bad_stack), "ValidationError"))
    bad_status = _wait_terminal(cf, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack naming a queue that already exists with other attributes: expected "
        f"ROLLBACK_COMPLETE, got {bad_status!r}"
    )
    got = _handler_reason(_reason(cf, bad_stack, "Queue"))
    want = ("Queue creation failed because the queue already exists", "AlreadyExists")
    assert got == want, f"CREATE_FAILED reason for Queue: {got!r}, expected {want!r}"
    resources = cf.describe_stack_resources(StackName=bad_stack).get("StackResources", [])
    statuses = [(r["LogicalResourceId"], r["ResourceStatus"]) for r in resources]
    assert statuses == [("Queue", "DELETE_COMPLETE")], (
        f"the handler attempted and failed the create, so rollback has nothing of its own to "
        f"delete: expected Queue DELETE_COMPLETE, got {statuses!r}"
    )
    unchanged = sqs.get_queue_attributes(QueueUrl=taken_url, AttributeNames=["VisibilityTimeout"])
    assert unchanged["Attributes"]["VisibilityTimeout"] == "45", (
        f"the pre-existing queue's VisibilityTimeout changed: {unchanged['Attributes']!r}"
    )

    free_name = ctx.unique_name("sim2real-behav-q-")
    good_stack = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(StackName=good_stack, TemplateBody=_queue_template(free_name, 99))
    ctx.on_cleanup(_teardown(lambda: cf.delete_stack(StackName=good_stack), "ValidationError"))
    good_status = _wait_terminal(cf, good_stack)
    assert good_status == "CREATE_COMPLETE", (
        f"the identical template with a free queue name: expected CREATE_COMPLETE, got "
        f"{good_status!r} — the collision case's failure was not isolated to the taken name"
    )
    free_url = sqs.get_queue_url(QueueName=free_name)["QueueUrl"]
    created = sqs.get_queue_attributes(QueueUrl=free_url, AttributeNames=["VisibilityTimeout"])
    assert created["Attributes"]["VisibilityTimeout"] == "99", (
        f"the free-name queue's VisibilityTimeout {created['Attributes']!r} != the declared 99"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
