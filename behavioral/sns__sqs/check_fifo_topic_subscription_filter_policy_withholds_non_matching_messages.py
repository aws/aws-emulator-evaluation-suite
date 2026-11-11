"""fifo-topic-subscription-filter-policy-withholds-non-matching-messages."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fifo-topic-subscription-filter-policy-withholds-non-matching-messages"
GROUP = "fifo-filtering"
SERVICES = ["sns", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a FIFO topic, a subscription's FilterPolicy admits only matching messages to its FIFO
    queue, so the later matching message follows the earlier one directly in group order, while an
    unfiltered sibling subscription receives every message."""
    sns = ctx.client("sns")
    topic_arn = _create_fifo_topic(ctx)
    filtered_url, filtered_arn = _create_fifo_queue_for_topic(ctx, topic_arn)
    plain_url, plain_arn = _create_fifo_queue_for_topic(ctx, topic_arn)

    sub_filtered = _subscribe_fifo(ctx, topic_arn, filtered_arn,
                                   attributes={"FilterPolicy": json.dumps({"color": ["red"]})})
    sub_plain = _subscribe_fifo(ctx, topic_arn, plain_arn)
    assert {sub_filtered, sub_plain} == set(_subs(sns, topic_arn)), (
        f"both subscriptions must be listed; got {_subs(sns, topic_arn)!r}")

    group = ctx.unique_name("sim2real-behav-sns-fifogrp-")
    red_body = ctx.unique_name("sim2real-red-")
    blue_body = ctx.unique_name("sim2real-blue-")
    red2_body = ctx.unique_name("sim2real-red-")
    sns.publish(TopicArn=topic_arn, Message=red_body, MessageGroupId=group,
                MessageDeduplicationId=f"{group}-red",
                MessageAttributes={"color": {"DataType": "String", "StringValue": "red"}})

    plain_after_red = _drain_until(ctx, plain_url, 1, timeout_s=60.0)
    filtered_after_red = _drain_until(ctx, filtered_url, 1, timeout_s=60.0)
    assert plain_after_red == [red_body], f"the unfiltered queue's first message must be the red one; got {plain_after_red!r}"
    assert filtered_after_red == [red_body], f"the filtered queue's first message must be the red one; got {filtered_after_red!r}"

    sns.publish(TopicArn=topic_arn, Message=blue_body, MessageGroupId=group,
                MessageDeduplicationId=f"{group}-blue",
                MessageAttributes={"color": {"DataType": "String", "StringValue": "blue"}})

    plain_after_blue = _drain_until(ctx, plain_url, 2, timeout_s=60.0, prior=plain_after_red)
    assert plain_after_blue == [red_body, blue_body], (
        f"the unfiltered queue must receive both messages in group order; got {plain_after_blue!r}")

    # A later matching message in the same group: FIFO order would put a leaked blue before it.
    sns.publish(TopicArn=topic_arn, Message=red2_body, MessageGroupId=group,
                MessageDeduplicationId=f"{group}-red2",
                MessageAttributes={"color": {"DataType": "String", "StringValue": "red"}})

    plain_after_red2 = _drain_until(ctx, plain_url, 3, timeout_s=60.0, prior=plain_after_blue)
    assert plain_after_red2 == [red_body, blue_body, red2_body], (
        f"the unfiltered queue must receive all three messages in group order; got {plain_after_red2!r}")
    filtered_after_red2 = _drain_until(ctx, filtered_url, 2, timeout_s=60.0, prior=filtered_after_red)
    assert filtered_after_red2 == [red_body, red2_body], (
        f"the filtered queue's next message must be the second red one, with the non-matching blue "
        f"withheld; got {filtered_after_red2!r}")


def _inner_message(body: str) -> str:
    """Unwrap the SNS Notification envelope and return its Message, or the body if it is not one."""
    try:
        envelope = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body
    if isinstance(envelope, dict) and envelope.get("Type") == "Notification":
        inner = envelope.get("Message")
        if isinstance(inner, str):
            return inner
    return body


def _create_fifo_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fifo-") + ".fifo"
    arn = sns.create_topic(
        Name=name, Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_fifo_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": arn, "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subs(sns, topic_arn: str) -> list[str]:
    return [s["SubscriptionArn"]
            for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic_arn)
            for s in page["Subscriptions"]]


def _subscribe_fifo(ctx, topic_arn: str, queue_arn: str, *,
                    attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe a FIFO queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn, "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: sns.unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s")


def _drain_until(ctx, queue_url: str, want_count: int, *, timeout_s: float, prior: list[str] | None = None) -> list[str]:
    """Long-poll until ``want_count`` bodies have arrived in total; returns them in arrival order."""
    sqs = ctx.client("sqs")
    collected = list(prior or [])
    deadline = time.monotonic() + timeout_s
    while len(collected) < want_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            collected.append(_inner_message(msg["Body"]))
    assert len(collected) >= want_count, (
        f"only {len(collected)} of {want_count} expected message(s) arrived within {timeout_s}s: {collected!r}")
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
