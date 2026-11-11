"""cfn-sqs-queue-readonly-queueurl-set-in-template-rejected-rolls-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-readonly-queueurl-set-in-template-rejected-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_REQUEST_TOKEN_RE = re.compile(r"RequestToken: [0-9a-f-]+")
_EXPECTED_REASON = (
    'Resource handler returned message: "QueueUrl is a read-only property." '
    '(RequestToken: <token>, HandlerErrorCode: InvalidRequest)'
)

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                   "DELETE_COMPLETE", "DELETE_FAILED"}


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _events(cfn, stack_id: str) -> list:
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return list(reversed(events))


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(queue_name: str, queue_url: str | None = None) -> str:
    props = {"QueueName": queue_name}
    if queue_url is not None:
        props["QueueUrl"] = queue_url
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": props}},
    })


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A template that sets AWS::SQS::Queue's readOnlyProperty QueueUrl (its
    primaryIdentifier) is refused at create time with the resource handler's exact
    InvalidRequest message and rolls the stack back; the same template without it deploys."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    bogus_url = f"https://sqs.{ctx.region}.amazonaws.com/111122223333/not-the-real-queue"

    good_queue = ctx.unique_name("sim2real-behav-cfnro-sqs-ok-")
    good = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cfnro-sqs-ok-stk-"),
        TemplateBody=_template(good_queue),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good))

    bad_queue = ctx.unique_name("sim2real-behav-cfnro-sqs-bad-")
    bad = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cfnro-sqs-bad-stk-"),
        TemplateBody=_template(bad_queue, bogus_url),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad))

    status = _wait_stack(cfn, good)
    assert status == "CREATE_COMPLETE", f"the control stack must deploy; got {status!r}"
    good_url = sqs.get_queue_url(QueueName=good_queue)["QueueUrl"]
    good_physical = cfn.describe_stack_resource(StackName=good, LogicalResourceId="Queue")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert good_physical == good_url, (
        f"the control queue's physical id {good_physical!r} is not SQS's own url {good_url!r}")

    status = _wait_stack(cfn, bad)
    assert status == "ROLLBACK_COMPLETE", (
        f"setting the readOnlyProperty QueueUrl must fail the stack and roll it back; got "
        f"{status!r}")

    queue_reasons = [e.get("ResourceStatusReason") for e in _events(cfn, bad)
                     if e["LogicalResourceId"] == "Queue" and e["ResourceStatus"] == "CREATE_FAILED"]
    masked = [_REQUEST_TOKEN_RE.sub("RequestToken: <token>", r) for r in queue_reasons]
    assert masked == [_EXPECTED_REASON], (
        f"the queue's CREATE_FAILED reason must be the handler's exact InvalidRequest message; "
        f"got {queue_reasons!r}")

    err = _error(lambda: sqs.get_queue_url(QueueName=bad_queue))
    assert err["Code"] == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the rejected queue must never have existed at SQS; got {err!r}")
    assert err["Message"] == "The specified queue does not exist.", (
        f"expected the standard NonExistentQueue message, got {err['Message']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
