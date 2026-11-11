"""fifo-throughput-scope-message-group-narrows-the-deduplication-scope."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fifo-throughput-scope-message-group-narrows-the-deduplication-scope"
GROUP = "fifo-topic"
SERVICES = ["sns"]

_SCENARIO = "sns-fifo-throughput-scope"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Under FifoThroughputScope=Topic a reused dedup id in another message group is accepted but
    not delivered; under MessageGroup (topic and paired queue) both are delivered, and an in-group
    duplicate is still suppressed.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/fifo-message-dedup.html"""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_fifo_topic(ctx)
    queue_url, queue_arn = _create_fifo_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn,
                           attributes={"RawMessageDelivery": "true"})

    scope = sns.get_topic_attributes(
        TopicArn=topic_arn)["Attributes"].get("FifoThroughputScope")
    assert scope == "Topic", (
        "phase 1 requires FifoThroughputScope='Topic' on the topic this check created "
        f"(set explicitly at CreateTopic, since a fresh topic omits the attribute from "
        f"GetTopicAttributes entirely rather than defaulting it to a readable value); "
        f"GetTopicAttributes read {scope!r}"
    )

    group_a = "sim2real-group-a"
    group_b = "sim2real-group-b"

    # ---- phase 1: Topic scope — one dedup id spans both groups ----------------------------
    dedup_1 = ctx.unique_name("sim2real-dedup-")
    first_wins = ctx.unique_name("sim2real-behav-fifoscope-topic-first-")
    cross_group_twin = ctx.unique_name("sim2real-behav-fifoscope-topic-twin-")

    started = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=first_wins, MessageGroupId=group_a,
                MessageDeduplicationId=dedup_1)
    accepted = sns.publish(TopicArn=topic_arn, Message=cross_group_twin,
                           MessageGroupId=group_b, MessageDeduplicationId=dedup_1)
    assert accepted.get("MessageId"), (
        "a duplicate MessageDeduplicationId must be ACCEPTED (documented: 'accepted "
        f"successfully but aren't delivered'), not refused; got {accepted!r}"
    )

    seen = _await_bodies(
        ctx, queue_url, {first_wins}, timeout_s=90.0,
        description=("under Topic scope the FIRST message with the deduplication id must be "
                     "delivered; without it the absence below would just mean broken wiring"),
        forbidden={cross_group_twin},
    )
    latency = max(seen[first_wins] - started, 1.0)
    window = max(3.0 * latency, 15.0)
    leaked = _drain(ctx, queue_url, window_s=window)
    assert leaked == [], (
        f"under FifoThroughputScope=Topic a second publish reusing the deduplication id in a "
        f"DIFFERENT message group must never be delivered; a {window:.0f}s window (>=3x the "
        f"measured latency of {latency:.1f}s), begun after the first message arrived, produced "
        f"{leaked!r}"
    )
    approx = int(sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"]["ApproximateNumberOfMessages"])
    assert approx == 0, (
        "second independent observable for the absence: expected ApproximateNumberOfMessages "
        f"== 0 on the FIFO queue, got {approx}"
    )

    # ---- phase 2: change exactly one attribute and DEMAND both deliveries ------------------
    #
    # The topic scope alone is not observable at a FIFO queue left at DeduplicationScope='queue':
    # SNS forwards its MessageDeduplicationId and the queue re-applies queue-wide dedup to it.
    # _create_fifo_queue_for_topic pairs the queue to 'messageGroup' for that reason.
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="FifoThroughputScope",
                             AttributeValue="MessageGroup")
    _poll_until(
        lambda: sns.get_topic_attributes(
            TopicArn=topic_arn)["Attributes"].get("FifoThroughputScope"),
        lambda value: value == "MessageGroup",
        timeout_s=60.0,
        interval_s=2.0,
        description="GetTopicAttributes reflects FifoThroughputScope=MessageGroup",
    )

    dedup_2 = ctx.unique_name("sim2real-dedup-")
    in_group_a = ctx.unique_name("sim2real-behav-fifoscope-group-a-")
    in_group_b = ctx.unique_name("sim2real-behav-fifoscope-group-b-")
    sns.publish(TopicArn=topic_arn, Message=in_group_a, MessageGroupId=group_a,
                MessageDeduplicationId=dedup_2)
    sns.publish(TopicArn=topic_arn, Message=in_group_b, MessageGroupId=group_b,
                MessageDeduplicationId=dedup_2)

    # _await_bodies raises unless BOTH arrive, and immediately if phase 1's suppressed twin
    # turns up late.
    _await_bodies(
        ctx, queue_url, {in_group_a, in_group_b}, timeout_s=90.0,
        description=("under FifoThroughputScope=MessageGroup (topic AND queue paired) the SAME "
                     "deduplication id in two different message groups must yield TWO "
                     "deliveries — this is the beat that proves the attribute changed the "
                     "behaviour rather than dedup being switched off or on wholesale"),
        forbidden={cross_group_twin},
    )

    # A duplicate WITHIN one group must still be suppressed under MessageGroup scope: the
    # attribute narrows the scope, it does not disable deduplication.
    same_group_twin = ctx.unique_name("sim2real-behav-fifoscope-same-group-twin-")
    sns.publish(TopicArn=topic_arn, Message=same_group_twin, MessageGroupId=group_a,
                MessageDeduplicationId=dedup_2)
    residual = _drain(ctx, queue_url, window_s=window)
    assert residual == [], (
        "narrowing the scope to MessageGroup must not disable deduplication inside a group: "
        f"reusing {dedup_2!r} in {group_a!r} was delivered anyway ({residual!r}) during a "
        f"{window:.0f}s window"
    )


def _create_fifo_topic(ctx) -> str:
    """CreateTopic for a FIFO topic (name suffixed .fifo, FifoTopic=true), tagged, with
    DeleteTopic registered immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        # Set explicitly: a fresh FIFO topic omits FifoThroughputScope from GetTopicAttributes.
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false",
                   "FifoThroughputScope": "Topic"},
        Tags=_tags_kv(),
    )["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_fifo_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic publish to it.

    DeduplicationScope='messageGroup' is required: a queue-wide-dedup queue re-collapses the
    cross-group duplicate the topic's MessageGroup scope decided to deliver.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "DeduplicationScope": "messageGroup",
                   "FifoThroughputLimit": "perMessageGroupId"},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
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


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"subscription {sub_arn} leaves PendingConfirmation",
    )
    return sub_arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str, forbidden: set[str] | None = None) -> dict[str, float]:
    """Long-poll until every wanted body is seen; raise on the deadline or on a forbidden body.

    Returns {body: monotonic time first seen} so the caller can calibrate an absence window.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if forbidden and body in forbidden:
                raise AssertionError(
                    f"{description}: a body that must never be delivered arrived: {body!r}"
                )
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s"
            )
    return seen


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return every body seen."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
