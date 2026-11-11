"""cfn-subscription-raw-message-delivery-non-boolean-rejected-creates-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-subscription-raw-message-delivery-non-boolean-rejected-creates-nothing"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_DEADLINE_S = 300.0

_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)
_PROPERTY_ROWS = [(
    "Subscription", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "Property [RawMessageDelivery] expected type: Boolean, found: String",
    "/Resources/Subscription/Properties/RawMessageDelivery",
)]


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A stack whose AWS::SNS::Subscription RawMessageDelivery is not a boolean fails early property
    validation at that path before any resource exists, while the same template with a boolean
    deploys and the subscription, queue and queue policy read back from SNS and SQS.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-behav-cfnrawval-")

    bad_stack = ctx.unique_name("sim2real-behav-cfnrawval-bad-")
    bad_id = _create(ctx, cfn, bad_stack, _template(queue_name, "not-a-boolean"))
    bad_status = _settle(cfn, bad_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"

    rows = _rows_for(_events(cfn, bad_id), bad_stack)
    assert _contains_subsequence(rows, [
        ("CREATE_FAILED", _VALIDATION_REASON),
        ("ROLLBACK_COMPLETE", None),
    ]), f"the decisive stack events must include this subsequence, got {rows!r}"
    found = _validation_errors(cfn, bad_id)
    assert found == _PROPERTY_ROWS, (
        f"VALIDATION_ERROR rows expected {_PROPERTY_ROWS!r}, got {found!r}"
    )

    code, message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the rejected stack must never have created the queue, got {code!r}: {message!r}"
    )
    assert message == "The specified queue does not exist.", (
        f"unexpected message for a queue the rejected stack never created: {message!r}"
    )

    # Positive control: the same template with a real boolean deploys and the queue exists.
    good_stack = ctx.unique_name("sim2real-behav-cfnrawval-good-")
    good_id = _create(ctx, cfn, good_stack, _template(queue_name + "-ok", "true"))
    good_status = _settle(cfn, good_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    url = sqs.get_queue_url(QueueName=queue_name + "-ok")["QueueUrl"]
    queue_ref = _physical_id(cfn, good_id, "Queue")
    assert url == queue_ref, f"SQS's own queue URL {url!r} != the stack's Queue Ref {queue_ref!r}"
    queue_attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn", "Policy"])[
        "Attributes"]
    queue_arn = queue_attrs["QueueArn"]
    assert queue_arn == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{queue_name}-ok", (
        f"queue ARN {queue_arn!r} is not the documented form for {queue_name + '-ok'!r}"
    )
    topic_arn = sns.get_topic_attributes(TopicArn=_physical_id(cfn, good_id, "Topic"))[
        "Attributes"]["TopicArn"]
    statements = [
        (s.get("Sid"), s.get("Effect"), s.get("Action"), s.get("Resource"), s.get("Condition"))
        for s in json.loads(queue_attrs.get("Policy", "{}")).get("Statement", [])
    ]
    want_statements = [(
        "AllowThisTopic", "Allow", "sqs:SendMessage", queue_arn,
        {"ArnEquals": {"aws:SourceArn": topic_arn}},
    )]
    assert statements == want_statements, (
        f"queue policy statements read back as {statements!r}, expected {want_statements!r}"
    )

    sub_arn = _physical_id(cfn, good_id, "Subscription")
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    got = (attrs.get("TopicArn"), attrs.get("Protocol"), attrs.get("Endpoint"),
           attrs.get("RawMessageDelivery"))
    want = (topic_arn, "sqs", queue_arn, "true")
    assert got == want, f"subscription (TopicArn, Protocol, Endpoint, RawMessageDelivery) {got!r} != {want!r}"


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _validation_errors(cfn, stack_id: str) -> list[tuple]:
    """``(logical id, name, status, mode, reason, path)`` of every VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
             e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _template(queue_name: str, raw_message_delivery: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowThisTopic",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                        }],
                    },
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "DependsOn": "QueuePolicy",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "RawMessageDelivery": raw_message_delivery,
                },
            },
        },
    })


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows_for(events: list[dict], logical_id: str) -> list[tuple]:
    """``(ResourceStatus, ResourceStatusReason)`` for every event on ``logical_id``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _contains_subsequence(rows: list[tuple], wanted: list[tuple]) -> bool:
    """True if ``wanted`` appears in ``rows``, in order, not necessarily contiguous."""
    it = iter(rows)
    return all(any(row == w for row in it) for w in wanted)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body,
        Tags=[{"Key": "sim2real", "Value": CHECK}], **kw,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
