"""stack-deploys-real-queue."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-deploys-real-queue"
GROUP = 'e2e_workflows'
SERVICES = ['cloudformation']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


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

def _simple_queue_template(queue_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "Tags": [{"Key": "sim2real-behav", "Value": queue_name}],
                },
            }
        },
    })

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
    (code, message)."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return _refusal(exc, status=status)
        if time.monotonic() > deadline:
            raise AssertionError(f"expected a refusal within {POLL_BUDGET_S}s, still accepted: {result!r}")
        time.sleep(5)


def _assert_queue_gone(sqs, queue_name, queue_url):
    """The three gone beats for a deleted queue: no URL by name, unlisted, refuses a send."""
    # AWS: a deleted queue answers AWS.SimpleQueueService.NonExistentQueue 400; a deletion takes
    # up to 60 seconds to propagate, so both refusals are polled.
    gone = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
    got = _poll_refused(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert got == gone, f"GetQueueUrl on the deleted queue: expected {gone}, got {got!r}"
    deadline = time.monotonic() + POLL_BUDGET_S
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


def _receive_body(sqs, queue_url, timeout_s=30):
    """Bounded-retry receive; raises if nothing arrives within timeout_s."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        if messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return messages[0]["Body"]
        time.sleep(1)
    raise AssertionError(f"no message received from {queue_url} within {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """CFN stack provisions a real, working SQS queue: it is visible in SQS's own
    listing, it accepts a real send/receive round trip (not just metadata), and
    deleting the stack actually removes it rather than leaving it to linger."""
    cf = ctx.client("cloudformation")
    queue_name = ctx.unique_name("sim2real-behav-queue-")
    name, stack_id = _create_and_wait(ctx, cf, _simple_queue_template(queue_name))

    sqs = ctx.client("sqs")
    resp = sqs.list_queues(QueueNamePrefix=queue_name)
    urls = resp.get("QueueUrls", [])
    matching = [url for url in urls if url.rstrip("/").endswith(f"/{queue_name}")]
    assert len(matching) == 1, f"expected exactly one ListQueues URL ending /{queue_name}, got {urls!r}"
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]

    body = f"sim2real-probe-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    received = _receive_body(sqs, queue_url)
    assert received == body, (
        f"stack-provisioned queue {queue_name} did not round-trip the probe message: "
        f"sent {body!r}, received {received!r}"
    )

    cf.delete_stack(StackName=name)
    outcome = _wait_deleted(cf, stack_id)
    assert outcome == "DELETE_COMPLETE", (
        f"stack {name} delete outcome via an independent DescribeStacks read by StackId was "
        f"{outcome!r}, expected DELETE_COMPLETE"
    )
    _assert_stack_gone(cf, name)
    _assert_queue_gone(sqs, queue_name, queue_url)


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
