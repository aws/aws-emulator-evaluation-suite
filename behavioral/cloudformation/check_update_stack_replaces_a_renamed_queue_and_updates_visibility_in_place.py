"""update-stack-replaces-a-renamed-queue-and-updates-visibility-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stack-replaces-a-renamed-queue-and-updates-visibility-in-place"
GROUP = 'e2e_workflows'
SERVICES = ['cloudformation']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
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
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _wait_deleted(cf, stack_id, timeout_s=POLL_BUDGET_S):
    """Poll DescribeStacks by StackId until DELETE_COMPLETE or DELETE_FAILED; return that status."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(2)

def _create_and_wait(ctx, cf, template):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return name and StackId."""
    name = ctx.unique_name("sim2real-behav-stk-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=template)["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name, stack_id

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
    # AWS: DescribeStacks by name of a deleted stack is ValidationError 400 "Stack with id <name>
    # does not exist" (polled: by-name lookup converges once DELETE_COMPLETE is reached).
    got = _poll_refused(lambda: cf.describe_stacks(StackName=name))
    assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"DescribeStacks on the deleted stack: got {got!r}"
    )
    # ListStacks keeps DELETE_COMPLETE summaries for 90 days, so only the active statuses are asked for.
    listed = [s["StackName"] for page in cf.get_paginator("list_stacks").paginate(
        StackStatusFilter=_ACTIVE_STACK_STATUSES) for s in page.get("StackSummaries", [])]
    assert name not in listed, f"deleted stack {name} still listed among active stacks"
    # AWS: UpdateStack(TemplateBody=...) on a missing stack is ValidationError "Stack [<name>] does not exist".
    got = _refused(lambda: cf.update_stack(StackName=name, TemplateBody=_DEAD_STACK_TEMPLATE))
    assert got == ("ValidationError", f"Stack [{name}] does not exist"), (
        f"UpdateStack on the deleted stack: got {got!r}"
    )


_DEAD_STACK_TEMPLATE = '{"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'


def _poll_refused(fn, *, status=400):
    """Repeat fn() until it is refused (bounded convergence), then return the refusal's
    (code, message).
    """
    deadline = time.monotonic() + _READ_POLL_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return _refusal(exc, status=status)
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a refusal within {_READ_POLL_S}s, still accepted: {result!r}")
        time.sleep(5)


def _assert_queue_gone(sqs, queue_name, queue_url):
    """The three gone beats for a deleted queue: no URL by name, unlisted, refuses a send."""
    # AWS: a deleted queue answers AWS.SimpleQueueService.NonExistentQueue 400; a deletion takes
    # up to 60 seconds to propagate, so both refusals are polled.
    gone = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
    got = _poll_refused(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert got == gone, f"GetQueueUrl on the deleted queue: expected {gone}, got {got!r}"
    deadline = time.monotonic() + _READ_POLL_S
    while True:
        urls = [u for page in sqs.get_paginator("list_queues").paginate(QueueNamePrefix=queue_name)
                for u in page.get("QueueUrls", [])]
        if not any(u.rstrip("/").endswith(f"/{queue_name}") for u in urls):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"deleted queue {queue_name} still listed by ListQueues: {urls!r}")
        time.sleep(5)
    got = _poll_refused(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="after-delete"))
    assert got == gone, f"SendMessage to the deleted queue: expected {gone}, got {got!r}"


def _queue_template(queue_name, visibility):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "VisibilityTimeout": visibility,
                    "Tags": [{"Key": "sim2real-behav", "Value": queue_name}],
                },
            }
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    })


def _update_and_wait(cf, name, template):
    """UpdateStack, then poll until the stack has moved past its pre-update state and is terminal; return the output."""
    def _seen():
        stack = cf.describe_stacks(StackName=name)["Stacks"][0]
        return stack["StackStatus"], stack.get("LastUpdatedTime")

    prior = _seen()
    cf.update_stack(StackName=name, TemplateBody=template)
    deadline = time.monotonic() + POLL_BUDGET_S
    moved, status = False, prior[0]
    while time.monotonic() < deadline:
        now = _seen()
        status = now[0]
        # A change of status or of LastUpdatedTime shows the update has run, however fast.
        moved = moved or now != prior
        if moved and status in _TERMINAL_STATES:
            break
        time.sleep(2)
    assert status == "UPDATE_COMPLETE", f"stack {name} update ended {status}, expected UPDATE_COMPLETE"
    return cf.describe_stacks(StackName=name)["Stacks"][0]["Outputs"][0]["OutputValue"]


def _round_trip(sqs, queue_url, body, timeout_s=30):
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
    raise AssertionError(f"no message received from {queue_url} within {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateStack changes a queue's VisibilityTimeout in place (same URL, new value) but replaces it
    when QueueName changes: the renamed queue works, the old one is deleted, and DeleteStack then
    removes the replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queue.html
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    first_name = ctx.unique_name("sim2real-behav-queue-a-")
    second_name = ctx.unique_name("sim2real-behav-queue-b-")
    name, stack_id = _create_and_wait(ctx, cf, _queue_template(first_name, 31))
    first_url = sqs.get_queue_url(QueueName=first_name)["QueueUrl"]

    in_place = _update_and_wait(cf, name, _queue_template(first_name, 97))
    assert in_place == first_url, f"a VisibilityTimeout change must keep the queue: Ref {in_place!r} vs {first_url!r}"
    vt = sqs.get_queue_attributes(QueueUrl=first_url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert vt == {"VisibilityTimeout": "97"}, f"the in-place update must set VisibilityTimeout 97, got {vt!r}"

    replaced = _update_and_wait(cf, name, _queue_template(second_name, 97))
    second_url = sqs.get_queue_url(QueueName=second_name)["QueueUrl"]
    assert replaced == second_url != first_url, f"a QueueName change must replace the queue: Ref {replaced!r}"
    physical = cf.describe_stack_resource(StackName=name, LogicalResourceId="Queue")["StackResourceDetail"]
    assert physical["PhysicalResourceId"] == second_url, f"the Queue resource's physical id: {physical!r}"
    body = f"after-replace-{second_name}"
    assert _round_trip(sqs, second_url, body) == body, "the replacement queue must round-trip a message"
    attrs = sqs.get_queue_attributes(QueueUrl=second_url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert attrs == {"VisibilityTimeout": "97"}, f"the replacement carries the template's value, got {attrs!r}"
    _assert_queue_gone(sqs, first_name, first_url)

    cf.delete_stack(StackName=name)
    outcome = _wait_deleted(cf, stack_id)
    assert outcome == "DELETE_COMPLETE", f"stack {name} delete outcome by StackId was {outcome!r}"
    _assert_stack_gone(cf, name)
    _assert_queue_gone(sqs, second_name, second_url)


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
