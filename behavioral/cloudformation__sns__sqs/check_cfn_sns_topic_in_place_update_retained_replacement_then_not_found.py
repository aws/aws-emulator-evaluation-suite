"""cfn-sns-topic-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sns-topic-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 60.0
#: A new topic, subscription or queue policy can lag for a short while, so a fresh publish follows.
_RESEND_S = 8.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: SNS's refusal of a topic that no longer exists.
_NOT_FOUND = ("NotFound", "Topic does not exist")


def _template(topic_name: str, display_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    # TopicName is create-only, so changing it replaces the topic.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "TopicName": topic_name,
                        "DisplayName": display_name,
                        "Tags": _TAGS,
                    },
                },
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "QueuePolicy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [{"Ref": "Queue"}],
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "sns.amazonaws.com"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                                }
                            ],
                        },
                    },
                },
                "Subscription": {
                    "Type": "AWS::SNS::Subscription",
                    "Properties": {
                        "TopicArn": {"Ref": "Topic"},
                        "Protocol": "sqs",
                        "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "RawMessageDelivery": "true",
                    },
                },
            },
            "Outputs": {
                "TopicArn": {"Value": {"Ref": "Topic"}},
                "TopicName": {"Value": {"Fn::GetAtt": ["Topic", "TopicName"]}},
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
    """A CloudFormation topic reads back as templated, updates in place and survives replacement.

    A publish reaches its queue; a DisplayName change keeps the topic, a TopicName change under
    UpdateReplacePolicy Retain keeps the old topic; delete: GetTopicAttributes NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sns-topic.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    first = ctx.unique_name("sim2real-cfntopic-a-")
    second = ctx.unique_name("sim2real-cfntopic-b-")
    stack_name = ctx.unique_name("sim2real-cfntopic-stack-")
    ref = {"stack": stack_name}
    first_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{first}"
    second_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{second}"

    # The replaced topic is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=first_arn))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, SNS's view, and a publish delivered
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "First"),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    queue_url = ids["Queue"]
    assert ids["Topic"] == first_arn, f"the topic's physical id must be its ARN {first_arn!r}"
    assert _outputs(stack) == {"TopicArn": first_arn, "TopicName": first}, (
        f"Ref and GetAtt TopicName: {_outputs(stack)!r}"
    )
    _assert_topic(sns, first_arn, "First")
    _assert_delivered(ctx, sns, sqs, first_arn, queue_url)

    # ---- 2. in-place: a new DisplayName, the same topic
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, "Second"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Topic"] == first_arn, (
        "an in-place update keeps the topic"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Topic"), first_arn, "Topic")
    _assert_topic(sns, first_arn, "Second")
    _assert_delivered(ctx, sns, sqs, first_arn, queue_url)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new topic, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, "Second"), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Topic"] == second_arn, (
        f"the stack must track the replacement {second_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Topic"), first_arn, second_arn, "Topic"
    )
    assert _outputs(stack) == {"TopicArn": second_arn, "TopicName": second}, (
        f"Ref and GetAtt TopicName after replacement: {_outputs(stack)!r}"
    )
    _assert_topic(sns, second_arn, "Second")
    _assert_delivered(ctx, sns, sqs, second_arn, queue_url)
    _assert_topic(sns, first_arn, "Second")

    # ---- 4. delete: SNS no longer knows the stack's topic
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: sns.get_topic_attributes(TopicArn=second_arn), _NOT_FOUND[0], f"topic {second}"
    )
    assert got == _NOT_FOUND, f"GetTopicAttributes after the stack delete answered {got!r}"


def _assert_topic(sns, arn: str, display_name: str) -> None:
    """GetTopicAttributes reports the template's topic exactly."""
    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
    got = {k: attrs.get(k) for k in ("TopicArn", "DisplayName")}
    want = {"TopicArn": arn, "DisplayName": display_name}
    assert got == want, f"GetTopicAttributes {arn}: {got!r}, expected {want!r}"


def _assert_delivered(ctx, sns, sqs, topic_arn: str, queue_url: str) -> None:
    """A publish to the topic arrives on the subscribed queue as the raw message.

    A fresh message is published every _RESEND_S until one of them arrives.
    """
    sent: list[str] = []
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    resend_at = 0.0
    got: list[str] = []
    while True:
        if time.monotonic() >= resend_at:
            sent.append(ctx.unique_name("publish-"))
            sns.publish(TopicArn=topic_arn, Message=sent[-1])
            resend_at = time.monotonic() + _RESEND_S
        for m in sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            got.append(m["Body"])
        if any(body in sent for body in got):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {topic_arn} delivered")
            raise AssertionError(
                f"no publish to {topic_arn} reached the queue within {timeout:.0f}s; "
                f"sent {sent!r}, received {got!r}"
            )


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
