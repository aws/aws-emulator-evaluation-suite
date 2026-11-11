"""update-stack-adds-then-removes-a-real-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stack-adds-then-removes-a-real-queue"
GROUP = 'stack_update'
SERVICES = ['cloudformation']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateStack really provisions and really removes resources: adding Q2 creates a queue that
    round-trips a message at SQS, dropping Q1 deletes that queue at SQS, and DeleteStack removes
    the stack and the remaining queue."""
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-stk-")
    q1 = ctx.unique_name("sim2real-behav-q1-")
    q2 = ctx.unique_name("sim2real-behav-q2-")

    stack_id = cf.create_stack(StackName=name, TemplateBody=_template({"Q1": q1}),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    status = _wait_terminal(cf, name)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    q1_url = sqs.get_queue_url(QueueName=q1)["QueueUrl"]

    # v2 adds Q2: it is created, reported with its URL, and serves traffic at SQS.
    cf.update_stack(StackName=name, TemplateBody=_template({"Q1": q1, "Q2": q2}))
    status = _wait_terminal(cf, name, prior="CREATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE after adding Q2, got {status!r}"
    resources = {
        r["LogicalResourceId"]: r
        for r in cf.describe_stack_resources(StackName=name)["StackResources"]
    }
    assert set(resources) == {"Q1", "Q2"}, f"expected resources Q1 and Q2, got {sorted(resources)!r}"
    assert resources["Q2"]["ResourceStatus"] == "CREATE_COMPLETE", resources["Q2"]
    q2_url = sqs.get_queue_url(QueueName=q2)["QueueUrl"]
    # AWS::SQS::Queue's physical id is the queue URL; the host part is endpoint-specific, so the
    # /<account>/<name> path identifies the queue.
    physical = resources["Q2"]["PhysicalResourceId"]
    assert physical.rstrip("/").endswith(f"/{ctx.account}/{q2}"), (
        f"expected Q2's PhysicalResourceId to be its queue URL (like {q2_url!r}), got {physical!r}"
    )
    body = f"sim2real-probe-{q2}"
    sqs.send_message(QueueUrl=q2_url, MessageBody=body)
    received = _receive_body(sqs, q2_url)
    assert received == body, f"queue {q2} did not round-trip the probe: sent {body!r}, got {received!r}"

    # v3 drops Q1: it is deleted at SQS while Q2 keeps answering.
    cf.update_stack(StackName=name, TemplateBody=_template({"Q2": q2}))
    status = _wait_terminal(cf, name, prior="UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE after removing Q1, got {status!r}"
    _assert_queue_gone(sqs, q1, q1_url)
    arn = sqs.get_queue_attributes(QueueUrl=q2_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert arn == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{q2}", f"unexpected Q2 arn {arn!r}"

    # DeleteStack removes the stack and the queue it still owns.
    cf.delete_stack(StackName=name)
    _wait_deleted(cf, stack_id)
    _assert_stack_gone(cf, name)
    _assert_queue_gone(sqs, q2, q2_url)


def _template(queues: dict) -> str:
    """One AWS::SQS::Queue per logical id, each with its explicit, tagged name."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            logical: {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": qname, "Tags": [{"Key": "sim2real-behav", "Value": qname}]},
            }
            for logical, qname in queues.items()
        },
    })


def _wait_terminal(cf, name, *, prior=None):
    """Poll DescribeStacks until the stack reaches a terminal state; return it. With ``prior``, the
    status the operation started from, a terminal read counts only after another status is seen."""
    deadline = time.monotonic() + POLL_BUDGET_S
    moved = prior is None
    while True:
        last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        moved = moved or last != prior
        if moved and last in _TERMINAL_STATES:
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {name} reached no terminal state (last={last!r})")
        time.sleep(2)


def _wait_deleted(cf, stack_id):
    """Poll DescribeStacks by StackId until DELETE_COMPLETE or DELETE_FAILED and require DELETE_COMPLETE."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert status == "DELETE_COMPLETE", f"DeleteStack of {stack_id} ended {status!r}"


def _receive_body(sqs, queue_url):
    """Receive one message, retrying until it arrives; delete it and return its body."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1,
                                       WaitTimeSeconds=2).get("Messages", [])
        if messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return messages[0]["Body"]
        if time.monotonic() > deadline:
            raise AssertionError(f"no message received from {queue_url}")


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


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
    refused = _poll_refused(lambda: cf.describe_stacks(StackName=name), ("ValidationError",))
    expected_message = f"Stack with id {name} does not exist"
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )
    # ListStacks keeps DELETE_COMPLETE summaries for 90 days, so only the active statuses are asked for.
    listed = [s["StackName"] for page in cf.get_paginator("list_stacks").paginate(
        StackStatusFilter=_ACTIVE_STACK_STATUSES) for s in page.get("StackSummaries", [])]
    assert name not in listed, f"deleted stack {name} still listed among active stacks"
    # AWS: UpdateStack(TemplateBody=...) on a missing stack is ValidationError "Stack [<name>] does not exist".
    refused = _expect_error(
        lambda: cf.update_stack(StackName=name, TemplateBody=_DEAD_STACK_TEMPLATE), ("ValidationError",)
    )
    expected_message = f"Stack [{name}] does not exist"
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )


_DEAD_STACK_TEMPLATE = '{"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'


def _poll_refused(fn, codes, *, status=400, contains=()):
    """Repeat fn() until it is refused (bounded convergence), then grade the refusal."""
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            result = fn()
        except ClientError as exc:
            _assert_error(exc, codes, status=status, contains=contains)
            return exc
        if time.monotonic() > deadline:
            raise AssertionError(f"expected {codes!r} within {POLL_BUDGET_S}s, still accepted: {result!r}")
        time.sleep(5)


_NO_SUCH_QUEUE_MESSAGE = "The specified queue does not exist."


def _assert_queue_gone(sqs, queue_name, queue_url):
    """The three gone beats for a deleted queue: no URL by name, unlisted, refuses a send."""
    # AWS: a deleted queue answers AWS.SimpleQueueService.NonExistentQueue 400 "The specified queue
    # does not exist."; a deletion takes up to 60 seconds to propagate, so both refusals are polled.
    refused = _poll_refused(lambda: sqs.get_queue_url(QueueName=queue_name),
                             ("AWS.SimpleQueueService.NonExistentQueue",))
    assert refused.response["Error"]["Message"] == _NO_SUCH_QUEUE_MESSAGE, (
        f"expected the message {_NO_SUCH_QUEUE_MESSAGE!r}, got {refused.response['Error']['Message']!r}"
    )
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        urls = [u for page in sqs.get_paginator("list_queues").paginate(QueueNamePrefix=queue_name)
                for u in page.get("QueueUrls", [])]
        if not any(u.rstrip("/").endswith(f"/{queue_name}") for u in urls):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"deleted queue {queue_name} still listed by ListQueues: {urls!r}")
        time.sleep(5)
    refused = _poll_refused(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="after-delete"),
                             ("AWS.SimpleQueueService.NonExistentQueue",))
    assert refused.response["Error"]["Message"] == _NO_SUCH_QUEUE_MESSAGE, (
        f"expected the message {_NO_SUCH_QUEUE_MESSAGE!r}, got {refused.response['Error']['Message']!r}"
    )


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
