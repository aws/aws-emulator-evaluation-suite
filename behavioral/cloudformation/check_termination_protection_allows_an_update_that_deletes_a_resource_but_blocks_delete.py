"""termination-protection-allows-an-update-that-deletes-a-resource-but-blocks-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "termination-protection-allows-an-update-that-deletes-a-resource-but-blocks-delete"
GROUP = 'termination_protection'
SERVICES = ['cloudformation']
#: Bounded convergence for a stack transition (create, delete, gone).
POLL_BUDGET_S = 180.0
#: Bound for a read-only convergence poll (a deleted stack or queue turning not-found).
_READ_POLL_S = 40.0


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=POLL_BUDGET_S):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        # A just-created stack is always describable, so any ClientError propagates.
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _status_or_gone(cf, stack_id):
    """The stack's StackStatus by StackId, or "GONE" when DescribeStacks refuses the id with the exact
    ValidationError "Stack with id <id> does not exist"; any other error raises.
    """
    try:
        return cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if (err.get("Code"), err.get("Message")) == ("ValidationError", f"Stack with id {stack_id} does not exist"):
            return "GONE"
        raise


def _delete_protected(cf, stack_id, timeout_s=600.0):
    """Teardown for a termination-protected stack, by StackId: disable protection, delete, and poll
    to DELETE_COMPLETE (or the not-found answer); DELETE_FAILED or a timeout raises.
    """
    if _status_or_gone(cf, stack_id) in ("DELETE_COMPLETE", "GONE"):
        return
    cf.update_termination_protection(StackName=stack_id, EnableTerminationProtection=False)
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = _status_or_gone(cf, stack_id)
        if status in ("DELETE_COMPLETE", "GONE"):
            return
        if status == "DELETE_FAILED":
            reason = cf.describe_stacks(StackName=stack_id)["Stacks"][0].get("StackStatusReason")
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {reason!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5)

def _wait_update(cf, name, prior, timeout_s=POLL_BUDGET_S):
    """After UpdateStack: poll until the status has left ``prior`` and is terminal; return it."""
    deadline = time.monotonic() + timeout_s
    moved, last = False, None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        moved = moved or last != prior
        if moved and last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} update not terminal within {timeout_s}s (last={last!r})")

def _refusal(exc, *, status=400):
    """(code, message) of a ClientError, after grading its HTTP status class."""
    err = exc.response.get('Error', {})
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {err.get('Code')}, got {got_status!r}"
    )
    return err.get('Code'), err.get('Message')


def _refused(fn, *, status=400):
    """(code, message) of the ClientError fn() raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return _refusal(exc, status=status)
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


_ACTIVE_STACK_STATUSES = [
    "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED",
    "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
    "REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
]


def _assert_stack_gone(cf, name):
    """The three gone beats for a deleted stack: not found by name, unlisted, not updatable."""
    # DescribeStacks by name of a deleted stack is refused ValidationError (polled: the by-name
    # lookup converges once DELETE_COMPLETE is reached).
    got = _poll_refused(lambda: cf.describe_stacks(StackName=name))
    assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"DescribeStacks on the deleted stack: got {got!r}"
    )
    # ListStacks keeps DELETE_COMPLETE summaries for 90 days, so only the active statuses are asked for.
    listed = [s["StackName"] for page in cf.get_paginator("list_stacks").paginate(
        StackStatusFilter=_ACTIVE_STACK_STATUSES) for s in page.get("StackSummaries", [])]
    assert name not in listed, f"deleted stack {name} still listed among active stacks"
    # UpdateStack(TemplateBody=...) on a missing stack is refused ValidationError.
    got = _refused(lambda: cf.update_stack(StackName=name, TemplateBody=_DEAD_STACK_TEMPLATE))
    assert got == ("ValidationError", f"Stack [{name}] does not exist"), (
        f"UpdateStack on the deleted stack: got {got!r}"
    )


_DEAD_STACK_TEMPLATE = '{"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'


def _poll_refused(fn):
    """Repeat fn() until it is refused (bounded convergence), then return the refusal's
    (code, message).
    """
    deadline = time.monotonic() + _READ_POLL_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return _refusal(exc)
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a refusal within {_READ_POLL_S}s, still accepted: {result!r}")
        time.sleep(5)


def _wait_deleted(cf, stack_id, timeout_s=POLL_BUDGET_S):
    """Poll by StackId until DELETE_COMPLETE or the not-found answer (returned); DELETE_FAILED raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _status_or_gone(cf, stack_id)
        if last in ("DELETE_COMPLETE", "GONE"):
            return last
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} not deleted within {timeout_s}s (last={last!r})")

def _queue_template(queue_name, visibility, with_queue=True):
    resources = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if with_queue:
        resources["Queue"] = {
            "Type": "AWS::SQS::Queue",
            "Properties": {
                "QueueName": queue_name,
                "VisibilityTimeout": visibility,
                "Tags": [{"Key": "sim2real-behav", "Value": queue_name}],
            },
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _round_trip(sqs, queue_url, body, timeout_s=30):
    """Send body and receive it back (bounded); return the received body."""
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
    raise AssertionError(f"no message received from {queue_url} within {timeout_s}s")


_NO_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Termination protection guards only DeleteStack: an UpdateStack on a protected stack that drops
    its queue completes and deletes the queue, the stack stays protected and its DeleteStack is still
    refused until protection is turned off.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-stk-")
    queue_name = ctx.unique_name("sim2real-behav-tpq-")
    stack_id = cf.create_stack(
        StackName=name,
        TemplateBody=_queue_template(queue_name, 30),
        EnableTerminationProtection=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_protected(cf, stack_id))
    assert _wait_terminal(cf, name) == "CREATE_COMPLETE", f"stack {name} did not reach CREATE_COMPLETE"
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    body = f"before-{queue_name}"
    assert _round_trip(sqs, queue_url, body) == body, "the stack's queue must round-trip a message"

    cf.update_stack(StackName=name, TemplateBody=_queue_template(queue_name, 30, with_queue=False))
    assert _wait_update(cf, name, "CREATE_COMPLETE") == "UPDATE_COMPLETE", f"the update on the protected stack {name} must complete"
    resources = {r["LogicalResourceId"] for r in cf.list_stack_resources(StackName=name)["StackResourceSummaries"]}
    assert resources == {"Handle"}, f"after the update the stack must hold only Handle, got {sorted(resources)}"
    got = _poll_refused(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert got == _NO_QUEUE, f"the queue the update dropped: expected {_NO_QUEUE}, got {got!r}"

    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    assert stack["EnableTerminationProtection"] is True, "the update must not switch termination protection off"
    got = _refused(lambda: cf.delete_stack(StackName=name))
    blocked = ("ValidationError", f"Stack [{name}] cannot be deleted while TerminationProtection is enabled")
    assert got == blocked, f"DeleteStack after the update: expected {blocked}, got {got!r}"
    assert cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"] == "UPDATE_COMPLETE"

    cf.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    cf.delete_stack(StackName=name)
    status = _wait_deleted(cf, stack_id)
    assert status in ("DELETE_COMPLETE", "GONE"), f"DeleteStack must succeed once protection is off, last={status!r}"
    _assert_stack_gone(cf, name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
