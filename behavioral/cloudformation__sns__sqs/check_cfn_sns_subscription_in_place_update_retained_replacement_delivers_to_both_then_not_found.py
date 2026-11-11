"""cfn-sns-subscription-in-place-update-retained-replacement-delivers-to-both-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sns-subscription-in-place-update-retained-replacement-delivers-to-both-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 60.0
#: A new or changed subscription can lag for a short while, so a fresh publish follows this often.
_RESEND_S = 8.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: SNS's refusal of a subscription that no longer exists.
_NOT_FOUND = ("NotFound", "Subscription does not exist")


def _queue_policy() -> dict:
    return {
        "Type": "AWS::SQS::QueuePolicy",
        "Properties": {
            "Queues": [{"Ref": "QueueA"}, {"Ref": "QueueB"}],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": [
                            {"Fn::GetAtt": ["QueueA", "Arn"]},
                            {"Fn::GetAtt": ["QueueB", "Arn"]},
                        ],
                        "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                    }
                ],
            },
        },
    }


def _template(endpoint_queue: str, raw: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": _TAGS}},
                "QueueA": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "QueueB": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "QueuePolicy": _queue_policy(),
                "Sub": {
                    "Type": "AWS::SNS::Subscription",
                    # Endpoint is create-only, so another queue replaces the subscription.
                    "UpdateReplacePolicy": "Retain",
                    "DependsOn": "QueuePolicy",
                    "Properties": {
                        "TopicArn": {"Ref": "Topic"},
                        "Protocol": "sqs",
                        "Endpoint": {"Fn::GetAtt": [endpoint_queue, "Arn"]},
                        "RawMessageDelivery": raw,
                    },
                },
            },
            "Outputs": {
                "TopicArn": {"Value": {"Ref": "Topic"}},
                "QueueAArn": {"Value": {"Fn::GetAtt": ["QueueA", "Arn"]}},
                "QueueBArn": {"Value": {"Fn::GetAtt": ["QueueB", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation subscription reads back, updates in place and survives replacement.

    A RawMessageDelivery change keeps it and changes the envelope; an Endpoint change under
    UpdateReplacePolicy Retain delivers one publish to both queues; delete: NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-subscription.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-cfnsub-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced subscription is retained; teardown removes it if the stack delete did not.
    ctx.on_cleanup(lambda: _unsubscribe(sns, retained.get("arn")))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, SNS's view, and a raw delivery to queue A
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template("QueueA", "true"),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    ids = _physical_ids(cfn, ref["stack"])
    first_arn, queue_a, queue_b = ids["Sub"], ids["QueueA"], ids["QueueB"]
    retained["arn"] = first_arn
    topic_arn = outputs["TopicArn"]
    _assert_subscription(sns, first_arn, topic_arn, outputs["QueueAArn"], "true")
    _deliver(ctx, sqs, queue_a, topic_arn, raw=True, publish=_publisher(ctx, sns, topic_arn))

    # ---- 2. in-place: RawMessageDelivery off, the same subscription
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template("QueueA", "false"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Sub"] == first_arn, (
        "an in-place update keeps the subscription"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Sub"), first_arn, "Sub")
    _assert_subscription(sns, first_arn, topic_arn, outputs["QueueAArn"], "false")
    publish = _publisher(ctx, sns, topic_arn)
    _deliver(ctx, sqs, queue_a, topic_arn, raw=False, publish=publish, changed=True)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new subscription, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template("QueueB", "false"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    second_arn = _physical_ids(cfn, ref["stack"])["Sub"]
    assert second_arn != first_arn, (
        f"the replacement must be a new subscription, still {first_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Sub"), first_arn, second_arn, "Sub"
    )
    _assert_subscription(sns, second_arn, topic_arn, outputs["QueueBArn"], "false")
    _assert_subscription(sns, first_arn, topic_arn, outputs["QueueAArn"], "false")
    publish = _publisher(ctx, sns, topic_arn)
    body = _deliver(ctx, sqs, queue_b, topic_arn, raw=False, publish=publish)
    # The publish that reached the new subscription's queue B reaches the retained one's queue A.
    _deliver(ctx, sqs, queue_a, topic_arn, raw=False, sent=[body])

    # ---- 4. delete: SNS no longer knows the stack's subscription
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: sns.get_subscription_attributes(SubscriptionArn=second_arn),
        _NOT_FOUND[0],
        f"subscription {second_arn}",
    )
    assert got == _NOT_FOUND, f"GetSubscriptionAttributes after the stack delete answered {got!r}"


def _assert_subscription(sns, arn: str, topic_arn: str, queue_arn: str, raw: str) -> None:
    """GetSubscriptionAttributes reports the template's subscription exactly."""
    attrs = sns.get_subscription_attributes(SubscriptionArn=arn)["Attributes"]
    keys = (
        "SubscriptionArn",
        "TopicArn",
        "Protocol",
        "Endpoint",
        "RawMessageDelivery",
        "PendingConfirmation",
    )
    got = {k: attrs.get(k) for k in keys}
    want = {
        "SubscriptionArn": arn,
        "TopicArn": topic_arn,
        "Protocol": "sqs",
        "Endpoint": queue_arn,
        "RawMessageDelivery": raw,
        "PendingConfirmation": "false",
    }
    assert got == want, f"GetSubscriptionAttributes {arn}: {got!r}, expected {want!r}"


def _publisher(ctx, sns, topic_arn: str):
    """A function that publishes a fresh message to the topic and appends it to a list."""

    def publish(sent: list[str]) -> None:
        sent.append(ctx.unique_name("publish-"))
        sns.publish(TopicArn=topic_arn, Message=sent[-1])

    return publish


def _deliver(
    ctx, sqs, url: str, topic_arn: str, *, raw: bool, publish=None, sent=None, changed=False
) -> str:
    """Receive on *url* until one of the *sent* messages arrives; assert its form and return it.

    A raw delivery is the message itself, otherwise an SNS Notification envelope of it. Right after
    a RawMessageDelivery change (*changed*) a delivery in the old form is skipped, else it fails.
    *publish* adds a fresh message every _RESEND_S.
    """
    sent = [] if sent is None else sent
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
            if raw and m["Body"] in sent:
                return m["Body"]
            envelope = _envelope(m["Body"])
            if not raw and envelope.get("Message") in sent:
                shape = (envelope.get("Type"), envelope.get("TopicArn"))
                assert shape == ("Notification", topic_arn), (
                    f"{url} must receive a Notification envelope from {topic_arn}: {envelope!r}"
                )
                return envelope["Message"]
            other_form = envelope.get("Message") in sent if raw else m["Body"] in sent
            assert changed or not other_form, (
                f"{url} must receive {'raw' if raw else 'enveloped'} deliveries, got {m['Body']!r}"
            )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} delivered a message")
            raise AssertionError(
                f"none of {sent!r} arrived on {url} {'raw' if raw else 'enveloped'} within "
                f"{timeout:.0f}s; received {got!r}"
            )


def _envelope(body: str) -> dict:
    """The SNS envelope a body holds, or {} for a raw body."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _unsubscribe(sns, arn: str | None) -> None:
    if arn is None:
        return
    try:
        sns.unsubscribe(SubscriptionArn=arn)
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
