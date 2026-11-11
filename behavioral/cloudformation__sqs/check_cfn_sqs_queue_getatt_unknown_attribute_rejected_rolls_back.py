"""cfn-sqs-queue-getatt-unknown-attribute-rejected-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-getatt-unknown-attribute-rejected-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_BAD_ATTRIBUTE = "NoSuchAttr"
_REASON = f"Requested attribute {_BAD_ATTRIBUTE} does not exist in schema for AWS::SQS::Queue"

_STACK = "<stack>"
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


def _rows(cfn, stack_id: str) -> list[tuple]:
    """``(logical id, status, reason)`` of every stack event, oldest first; the stack is ``<stack>``."""
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return [(_STACK if e["LogicalResourceId"] == e["StackName"] else e["LogicalResourceId"],
             e["ResourceStatus"], e.get("ResourceStatusReason")) for e in reversed(events)]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """True when every ``(logical id, status)`` of ``wanted`` occurs in ``rows`` in that order."""
    it = iter(r[:2] for r in rows)
    return all(w in it for w in wanted)


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(queue_name: str, *, bad: bool) -> str:
    outputs = {}
    if bad:
        outputs["Bad"] = {"Value": {"Fn::GetAtt": ["Queue", _BAD_ATTRIBUTE]}}
    else:
        outputs["QueueArn"] = {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
        },
        "Outputs": outputs,
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Fn::GetAtt naming an attribute AWS::SQS::Queue lacks passes ValidateTemplate and
    CreateStack, then fails the stack with the exact schema reason, rolls back and deletes
    the queue; the same template with only the declared Arn output deploys."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    good_queue = ctx.unique_name("sim2real-behav-cfnga-sqs-ok-")
    good = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cfnga-sqs-ok-stk-"),
        TemplateBody=_template(good_queue, bad=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good))

    bad_queue = ctx.unique_name("sim2real-behav-cfnga-sqs-bad-")
    bad_template = _template(bad_queue, bad=True)
    validated = cfn.validate_template(TemplateBody=bad_template)
    assert validated.get("Parameters") == [], (
        f"ValidateTemplate accepts the template; it answered {validated!r}")

    bad = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cfnga-sqs-bad-stk-"),
        TemplateBody=bad_template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad))

    status = _wait_stack(cfn, good)
    assert status == "CREATE_COMPLETE", f"the control stack must deploy; got {status!r}"

    status = _wait_stack(cfn, bad)
    assert status == "ROLLBACK_COMPLETE", (
        f"an unknown GetAtt attribute must fail the stack and roll it back; got {status!r}")

    outputs = _outputs(cfn, good)
    good_url = sqs.get_queue_url(QueueName=good_queue)["QueueUrl"]
    good_arn = sqs.get_queue_attributes(QueueUrl=good_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    assert outputs.get("QueueArn") == good_arn, (
        f"GetAtt Arn of the control queue must equal SQS's QueueArn {good_arn!r}; got {outputs!r}")

    # The output failure is reported only on the stack's own rollback event, so that row's
    # reason is graded, together with the terminal rows that bracket it.
    rows = _rows(cfn, bad)
    reasons = [r[2] for r in rows if r[:2] == (_STACK, "ROLLBACK_IN_PROGRESS")]
    assert reasons == [f"{_REASON}. Rollback requested by user."], (
        f"the stack's rollback reason must name the unknown attribute; got {reasons!r}")
    wanted = [("Queue", "CREATE_COMPLETE"), (_STACK, "ROLLBACK_IN_PROGRESS"),
              ("Queue", "DELETE_COMPLETE"), (_STACK, "ROLLBACK_COMPLETE")]
    assert _in_order(rows, wanted), (
        f"the queue must be built, then deleted by the rollback; expected {wanted!r} in "
        f"order, got {[r[:2] for r in rows]!r}")

    err = _error(lambda: sqs.get_queue_url(QueueName=bad_queue))
    assert err["Code"] == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the rolled-back queue: got {err!r}")
    assert err["Message"] == "The specified queue does not exist.", (
        f"the rolled-back queue: message was {err['Message']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
