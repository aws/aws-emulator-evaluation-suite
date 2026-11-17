"""deploy-cfn-sns-fifo-topic-fifothroughputscope-updates-in-place-and-keeps-group-order."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sns-fifo-topic-fifothroughputscope-updates-in-place-and-keeps-group-order"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 90.0
_POLL_S = 2.0

_NOT_FOUND = ("NotFound", "Topic does not exist")
_GROUP = "orders"


def _template(topic_name: str, scope: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name,
                    "FifoTopic": True,
                    "ContentBasedDeduplication": True,
                    "FifoThroughputScope": scope,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation FIFO topic's FifoThroughputScope reads back as templated, updates in place
    from Topic to MessageGroup scope, and per-group publish order still holds afterward.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/fifo-high-throughput.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_name = ctx.unique_name("sim2real-cfnfts-") + ".fifo"
    stack_name = ctx.unique_name("sim2real-cfnfts-stack-")
    topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{topic_name}"
    ref = {"stack": stack_name}

    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: FifoThroughputScope Topic, read back
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(topic_name, "Topic"),
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    assert ids["Topic"] == topic_arn, f"the topic's physical id must be its ARN, got {ids!r}"
    _assert_topic(sns, topic_arn, {
        "FifoThroughputScope": "Topic", "FifoTopic": "true", "ContentBasedDeduplication": "true",
    })

    queue_url = _create_subscribed_fifo_queue(ctx, sqs, sns, topic_arn)

    first_two = [ctx.unique_name("m1-"), ctx.unique_name("m2-")]
    for body in first_two:
        sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=_GROUP)
    delivered = _receive_n(ctx, sqs, queue_url, len(first_two))
    assert delivered == first_two, f"expected {first_two!r} in publish order, got {delivered!r}"

    # ---- 2. in-place update: MessageGroup scope, the same topic, group order still holds
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(topic_name, "MessageGroup"))
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Topic"] == topic_arn, (
        "a FifoThroughputScope change must update the topic in place, not replace it"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Topic"), topic_arn)
    _assert_topic(sns, topic_arn, {"FifoThroughputScope": "MessageGroup"})

    next_two = [ctx.unique_name("m3-"), ctx.unique_name("m4-")]
    for body in next_two:
        sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=_GROUP)
    delivered = _receive_n(ctx, sqs, queue_url, len(next_two))
    assert delivered == next_two, (
        f"group {_GROUP!r} order must hold after the scope change, expected {next_two!r}, "
        f"got {delivered!r}"
    )

    # ---- 3. delete: SNS no longer knows the topic
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: sns.get_topic_attributes(TopicArn=topic_arn), _NOT_FOUND[0])
    assert got == _NOT_FOUND, f"GetTopicAttributes after the stack delete answered {got!r}"


def _create_subscribed_fifo_queue(ctx, sqs, sns, topic_arn: str) -> str:
    """A tagged FIFO SQS queue, policy-permitted and raw-subscribed to *topic_arn*."""
    queue_name = ctx.unique_name("sim2real-cfnfts-queue-") + ".fifo"
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real": CHECK},
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
    return queue_url


def _assert_topic(sns, topic_arn: str, want: dict) -> None:
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    got = {k: attrs.get(k) for k in want}
    assert got == want, f"GetTopicAttributes for {topic_arn}: {got!r}, expected {want!r}"


def _receive_n(ctx, sqs, queue_url: str, n: int) -> list[str]:
    """The bodies of the next *n* messages the queue delivers, in receive order."""
    got: list[str] = []
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    while len(got) < n:
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            AttributeNames=["MessageGroupId"],
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            got.append(m["Body"])
        if len(got) < n and time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with only {got!r} of {n} delivered")
            raise AssertionError(f"only {got!r} of {n} expected messages arrived within {timeout:.0f}s")
    return got[:n]


# ===== helpers =====


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
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
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"FifoThroughputScope must update the topic in place with no replacement, events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"the in-place update must complete on {physical_id!r}, events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _wait_error(ctx, fn, code: str):
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
