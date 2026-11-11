"""fifo-deduplication-collapses-duplicate-publish."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fifo-deduplication-collapses-duplicate-publish"
GROUP = 'fifo-topic'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-dedup-single"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, name, attributes=None):
    """CreateTopic (tagged) + register DeleteTopic cleanup; returns the TopicArn."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Attributes=attributes or {}, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=arn))
    return arn


def _create_queue_for_topic(ctx, topic_arn, name):
    """Create a real FIFO SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true"},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn, queue_arn, timeout_s=60.0):
    """Subscribe the queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


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


def _drain_until(ctx, queue_url, sentinel, timeout_s=90.0):
    """Receive until `sentinel` arrives; returns everything seen BEFORE it, in order."""
    sqs = ctx.client("sqs")
    seen = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            inner = _inner_message(msg.get("Body", ""))
            if inner == sentinel:
                return seen
            seen.append(inner)
    raise AssertionError(f"sentinel {sentinel!r} never arrived within {timeout_s}s; saw {seen!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Republishing the same MessageDeduplicationId inside the dedup window is collapsed: the
    Publish response is identical, and the FIFO queue at
    the destination receives exactly one copy of the pair, not two.
    """
    sns = ctx.client("sns")
    run_id = ctx.unique_name("sim2real-behav-sns-fifodedup-")
    topic_arn = _create_topic(ctx, run_id + ".fifo", attributes={"FifoTopic": "true"})
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, run_id + "-q.fifo")
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    dedup_id = ctx.unique_name("sim2real-behav-dedup-")
    first = sns.publish(
        TopicArn=topic_arn, Message="first-copy", MessageGroupId="group-a",
        MessageDeduplicationId=dedup_id,
    )
    second = sns.publish(
        TopicArn=topic_arn, Message="second-copy", MessageGroupId="group-a",
        MessageDeduplicationId=dedup_id,
    )
    assert second.get("MessageId") == first.get("MessageId"), (
        "expected duplicate publish to return the original MessageId, got "
        f"{first.get('MessageId')} then {second.get('MessageId')}"
    )
    assert second.get("SequenceNumber") == first.get("SequenceNumber"), (
        "expected duplicate publish to return the original SequenceNumber, got "
        f"{first.get('SequenceNumber')} then {second.get('SequenceNumber')}"
    )
    third = sns.publish(
        TopicArn=topic_arn, Message="third-copy", MessageGroupId="group-a",
        MessageDeduplicationId=ctx.unique_name("sim2real-behav-dedup-other-"),
    )
    assert third.get("MessageId") != first.get("MessageId"), (
        "expected a distinct dedup id to produce a distinct message"
    )
    assert int(third["SequenceNumber"]) > int(first["SequenceNumber"]), (
        "expected a distinct dedup id to advance the sequence number"
    )

    sentinel = "sentinel-copy"
    sns.publish(
        TopicArn=topic_arn, Message=sentinel, MessageGroupId="group-a",
        MessageDeduplicationId=ctx.unique_name("sim2real-behav-dedup-sentinel-"),
    )
    delivered = _drain_until(ctx, queue_url, sentinel, timeout_s=90.0)
    assert delivered == ["first-copy", "third-copy"], (
        "expected the FIFO queue to deliver exactly one copy of the deduplicated pair and "
        f"the distinct message, in that order; got {delivered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
