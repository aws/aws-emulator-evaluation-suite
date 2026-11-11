"""cfn-sqs-queue-policy-in-place-queues-change-gates-sns-delivery-then-removed."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-policy-in-place-queues-change-gates-sns-delivery-then-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A queue policy change can take up to 60 s to reach every SQS host.
_CONVERGE_CAP_S = 90.0
_RECEIVE_CAP_S = 90.0
#: A publish before the policy reached SQS is dropped, so a fresh publish follows this often.
_RESEND_S = 8.0
#: After the allowed queue received a publish, the denied queue is read this long for it.
_DENIED_WINDOW_S = 10.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: SNS's refusal of a topic that no longer exists.
_TOPIC_NOT_FOUND = ("NotFound", "Topic does not exist")


def _policy_document(queue_arns: list[str], topic_arn) -> dict:
    """The statement letting SNS send to *queue_arns* for the topic *topic_arn* only.

    One queue is a bare ARN: SQS reads a one-element Resource list back as the bare ARN, so the
    template states it in that form and the policy round-trips exactly.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arns[0] if len(queue_arns) == 1 else queue_arns,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }


def _template(queues: list[tuple[str, str]], all_queues: list[str]) -> str:
    """The topic, a raw subscription per queue in *all_queues*, a policy over *queues*."""
    subs = {
        f"Sub{i}": {
            "Type": "AWS::SNS::Subscription",
            "DependsOn": "Policy",
            "Properties": {
                "TopicArn": {"Ref": "Topic"},
                "Protocol": "sqs",
                "Endpoint": arn,
                "RawMessageDelivery": "true",
            },
        }
        for i, arn in enumerate(all_queues)
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": _TAGS}},
                # AWS::SQS::QueuePolicy has no create-only property, so no update replaces it.
                "Policy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [url for url, _ in queues],
                        "PolicyDocument": _policy_document(
                            [arn for _, arn in queues], {"Ref": "Topic"}
                        ),
                    },
                },
                **subs,
            },
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation queue policy decides which queue its topic's publishes reach.

    Queue A alone receives until a Queues change adds B in place (no property forces a
    replacement); deleting the stack removes both queues' Policy attribute.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queuepolicy.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    name_a = ctx.unique_name("sim2real-cfnqp-a-")
    name_b = ctx.unique_name("sim2real-cfnqp-b-")
    stack_name = ctx.unique_name("sim2real-cfnqp-stack-")
    ref = {"stack": stack_name}

    # The queues are the check's own, so the stack's policy is the only thing gating them.
    ctx.on_cleanup(lambda: _delete_queue(sqs, name_a))
    ctx.on_cleanup(lambda: _delete_queue(sqs, name_b))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    url_a = sqs.create_queue(QueueName=name_a, tags={"sim2real": CHECK})["QueueUrl"]
    url_b = sqs.create_queue(QueueName=name_b, tags={"sim2real": CHECK})["QueueUrl"]
    arn_a = _queue_arn(sqs, url_a)
    arn_b = _queue_arn(sqs, url_b)

    # ---- 1. create: the policy covers queue A only; SNS reaches A and not B
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template([(url_a, arn_a)], [arn_a, arn_b]),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    topic_arn = _outputs(stack)["TopicArn"]
    policy_id = _physical_ids(cfn, ref["stack"])["Policy"]
    _assert_policy(ctx, sqs, url_a, _policy_document([arn_a], topic_arn))
    _assert_policy(ctx, sqs, url_b, None)
    publish = _publisher(ctx, sns, topic_arn)
    sent: list[str] = []
    body = _receive(ctx, sqs, url_a, sent, publish)
    # SNS fans a publish out to every subscription at once; B's is refused by B's missing grant.
    _assert_withheld(ctx, sqs, url_b, sent, body)

    # ---- 2. in-place: the policy covers both queues, the same policy resource
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template([(url_a, arn_a), (url_b, arn_b)], [arn_a, arn_b]),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Policy"] == policy_id, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Policy"), policy_id, "Policy")
    both = _policy_document([arn_a, arn_b], topic_arn)
    _assert_policy(ctx, sqs, url_a, both)
    _assert_policy(ctx, sqs, url_b, both)
    sent = []
    body = _receive(ctx, sqs, url_b, sent, _publisher(ctx, sns, topic_arn))
    # The publish that reached B reaches A as well.
    _receive(ctx, sqs, url_a, [body], None)

    # ---- 3. delete: the queues outlive the stack without its policy; the topic is gone
    _delete_stack(ctx, cfn, ref["stack"])
    _assert_policy(ctx, sqs, url_a, None)
    _assert_policy(ctx, sqs, url_b, None)
    got = _wait_error(
        ctx,
        lambda: sns.get_topic_attributes(TopicArn=topic_arn),
        _TOPIC_NOT_FOUND[0],
        f"topic {topic_arn}",
    )
    assert got == _TOPIC_NOT_FOUND, f"GetTopicAttributes after the stack delete answered {got!r}"


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _assert_policy(ctx, sqs, url: str, want: dict | None) -> None:
    """GetQueueAttributes Policy is exactly the template's document, or absent for None.

    An empty Policy value is kept as it is, never read as absent.
    """

    def read():
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
            "Attributes", {}
        )
        return json.loads(attrs["Policy"]) if attrs.get("Policy") else attrs.get("Policy")

    got = _poll(ctx, read, lambda v: v == want, f"the Policy of {url}", _CONVERGE_CAP_S)
    assert got == want, f"Policy of {url}: {got!r}, expected {want!r}"


def _publisher(ctx, sns, topic_arn: str):
    """A function that publishes a fresh message to the topic and appends it to a list."""

    def publish(sent: list[str]) -> None:
        sent.append(ctx.unique_name("publish-"))
        sns.publish(TopicArn=topic_arn, Message=sent[-1])

    return publish


def _receive(ctx, sqs, url: str, sent: list[str], publish) -> str:
    """Receive on *url* until one of *sent* arrives raw and return it.

    *publish*, when given, adds a fresh message every _RESEND_S.
    """
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    resend_at = 0.0
    got: list[str] = []
    while True:
        if publish is not None and time.monotonic() >= resend_at:
            publish(sent)
            resend_at = time.monotonic() + _RESEND_S
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        ):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            got.append(m["Body"])
            if m["Body"] in sent:
                return m["Body"]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} received a publish")
            raise AssertionError(
                f"none of {sent!r} arrived on {url} within {timeout:.0f}s; received {got!r}"
            )


def _assert_withheld(ctx, sqs, url: str, sent: list[str], delivered: str) -> None:
    """None of *sent* reaches *url* within _DENIED_WINDOW_S after *delivered* reached its peer."""
    deadline = time.monotonic() + min(_DENIED_WINDOW_S, _budget_s(ctx, _DENIED_WINDOW_S))
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        ):
            assert m["Body"] not in sent, (
                f"{url} is outside the queue policy, yet received {m['Body']!r} (its peer "
                f"received {delivered!r})"
            )


def _delete_queue(sqs, name: str) -> None:
    try:
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap_s; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
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


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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


def _poll(ctx, read, ok, what: str, cap_s: float):
    """Re-read until ``ok(value)`` holds, for an eventually consistent read; the last value."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if ok(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last read {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
