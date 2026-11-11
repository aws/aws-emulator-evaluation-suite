"""cfn-sqs-queue-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 60.0
#: SQS documents up to 60 s for an attribute change to reach every read.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: SQS's refusal of a queue that no longer exists.
_NOT_FOUND = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")


def _template(queue_name: str, visibility_timeout: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    # QueueName is create-only, so changing it replaces the queue.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "QueueName": queue_name,
                        "VisibilityTimeout": visibility_timeout,
                        "MessageRetentionPeriod": 3600,
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
                "QueueName": {"Value": {"Fn::GetAtt": ["Queue", "QueueName"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation queue reads back as templated, updates in place and survives replacement.

    Messages round-trip; a VisibilityTimeout change keeps the queue, a QueueName change under
    UpdateReplacePolicy Retain keeps the old queue and its message; delete: NonExistentQueue.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    first = ctx.unique_name("sim2real-cfnq-a-")
    second = ctx.unique_name("sim2real-cfnq-b-")
    stack_name = ctx.unique_name("sim2real-cfnq-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced queue is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_queue(sqs, retained.get("url")))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, SQS's view, and a message round trip
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, 30),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_url = _physical_ids(cfn, ref["stack"])["Queue"]
    retained["url"] = first_url
    assert sqs.get_queue_url(QueueName=first)["QueueUrl"] == first_url, (
        f"the queue's physical id {first_url!r} must be the QueueUrl SQS answers for {first!r}"
    )
    first_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{first}"
    assert _outputs(stack) == {"QueueArn": first_arn, "QueueName": first}, (
        f"GetAtt outputs {_outputs(stack)!r}"
    )
    _assert_queue(ctx, sqs, first_url, first_arn, visibility_timeout="30")
    _assert_round_trip(ctx, sqs, first_url)

    # ---- 2. in-place: a new VisibilityTimeout, the same queue
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, 45), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Queue"] == first_url, (
        "an in-place update keeps the queue"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Queue"), first_url, "Queue")
    _assert_queue(ctx, sqs, first_url, first_arn, visibility_timeout="45")
    left_behind = ctx.unique_name("left-")
    sqs.send_message(QueueUrl=first_url, MessageBody=left_behind)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new queue, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, 45), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_url = _physical_ids(cfn, ref["stack"])["Queue"]
    assert second_url != first_url, f"the replacement must be a new queue, still {first_url!r}"
    assert sqs.get_queue_url(QueueName=second)["QueueUrl"] == second_url, (
        f"the stack's new physical id {second_url!r} must be the QueueUrl of {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Queue"), first_url, second_url, "Queue"
    )
    second_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{second}"
    assert _outputs(stack) == {"QueueArn": second_arn, "QueueName": second}, (
        f"GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_queue(ctx, sqs, second_url, second_arn, visibility_timeout="45")
    _assert_round_trip(ctx, sqs, second_url)
    _assert_queue(ctx, sqs, first_url, first_arn, visibility_timeout="45")
    kept = _receive(ctx, sqs, first_url)
    assert kept == [left_behind], (
        f"the retained queue must still hold the message sent before the replacement, got {kept!r}"
    )

    # ---- 4. delete: SQS no longer knows the stack's queue
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: sqs.get_queue_attributes(QueueUrl=second_url, AttributeNames=["QueueArn"]),
        _NOT_FOUND[0],
        f"queue {second}",
    )
    assert got == _NOT_FOUND, f"GetQueueAttributes after the stack delete answered {got!r}"


def _assert_queue(ctx, sqs, url: str, arn: str, *, visibility_timeout: str) -> None:
    """GetQueueAttributes reports the template's attributes exactly.

    The read is polled: SQS documents up to 60 s for an attribute change to reach every read.
    """
    names = ["QueueArn", "VisibilityTimeout", "MessageRetentionPeriod"]
    want = {
        "QueueArn": arn,
        "VisibilityTimeout": visibility_timeout,
        "MessageRetentionPeriod": "3600",
    }
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=names)["Attributes"]
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} showed {want!r}")
            raise AssertionError(f"GetQueueAttributes {url}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _assert_round_trip(ctx, sqs, url: str) -> None:
    body = ctx.unique_name("body-")
    sqs.send_message(QueueUrl=url, MessageBody=body)
    got = _receive(ctx, sqs, url)
    assert got == [body], f"ReceiveMessage on {url} returned {got!r}, expected [{body!r}]"


def _receive(ctx, sqs, url: str) -> list[str]:
    """Bodies of the first non-empty receive, each deleted after reading."""
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        messages = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        )
        if messages:
            for m in messages:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            return [m["Body"] for m in messages]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} delivered a message")
            raise AssertionError(f"no message arrived on {url} within {timeout:.0f}s")


def _delete_queue(sqs, url: str | None) -> None:
    if url is None:
        return
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
