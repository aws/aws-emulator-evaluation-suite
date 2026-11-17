"""deploy-cfn-sns-topic-tracingconfig-round-trips-in-place-and-keeps-delivering."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sns-topic-tracingconfig-round-trips-in-place-and-keeps-delivering"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 60.0
_RESEND_S = 8.0
_POLL_S = 2.0

_NOT_FOUND = ("NotFound", "Topic does not exist")


def _template(topic_name: str, tracing_config: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name,
                    "TracingConfig": tracing_config,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation topic's TracingConfig reads back as templated, updates in place between
    Active and PassThrough, and a publish still reaches a subscribed queue on both values.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-active-tracing.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_name = ctx.unique_name("sim2real-cfntrc-")
    stack_name = ctx.unique_name("sim2real-cfntrc-stack-")
    topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{topic_name}"
    ref = {"stack": stack_name}

    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: TracingConfig Active, read back, and a publish is actually delivered
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(topic_name, "Active"),
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    assert ids["Topic"] == topic_arn, f"the topic's physical id must be its ARN, got {ids!r}"
    assert _outputs(stack) == {"TopicArn": topic_arn}, f"stack outputs were {_outputs(stack)!r}"
    _assert_tracing_config(sns, topic_arn, "Active")

    queue_url, queue_arn = _create_subscribed_queue(ctx, sqs, sns, topic_arn)

    _assert_delivered(ctx, sns, sqs, topic_arn, queue_url)

    # ---- 2. in-place update: PassThrough, the same topic, delivery keeps working
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(topic_name, "PassThrough"))
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Topic"] == topic_arn, (
        "a TracingConfig change must update the topic in place, not replace it"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Topic"), topic_arn)
    _assert_tracing_config(sns, topic_arn, "PassThrough")
    _assert_delivered(ctx, sns, sqs, topic_arn, queue_url)

    # ---- 3. delete: SNS no longer knows the topic
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: sns.get_topic_attributes(TopicArn=topic_arn), _NOT_FOUND[0])
    assert got == _NOT_FOUND, f"GetTopicAttributes after the stack delete answered {got!r}"


def _create_subscribed_queue(ctx, sqs, sns, topic_arn: str):
    """A tagged SQS queue, policy-permitted and subscribed to *topic_arn*; registers its teardown."""
    queue_name = ctx.unique_name("sim2real-cfntrc-queue-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub_arn), "NotFound"))
    return queue_url, queue_arn


def _assert_tracing_config(sns, topic_arn: str, want: str) -> None:
    """GetTopicAttributes reports TracingConfig exactly as the template set it."""
    got = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get("TracingConfig")
    assert got == want, f"GetTopicAttributes TracingConfig for {topic_arn}: {got!r}, expected {want!r}"


def _assert_delivered(ctx, sns, sqs, topic_arn: str, queue_url: str) -> None:
    """A publish to the topic arrives on the subscribed queue, raw and unchanged.

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
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only *not_found* codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
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
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
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
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str) -> None:
    """The Topic's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"TracingConfig must update the topic in place with no replacement, events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"the in-place update must complete on {physical_id!r}, events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str):
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
                raise TimeoutError("run budget ended while the deleted topic still answered")
            raise AssertionError(f"the deleted topic still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
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
