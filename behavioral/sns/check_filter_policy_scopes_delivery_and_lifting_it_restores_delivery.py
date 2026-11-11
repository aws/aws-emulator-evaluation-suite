"""filter-policy-scopes-delivery-and-lifting-it-restores-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "filter-policy-scopes-delivery-and-lifting-it-restores-delivery"
GROUP = 'delivery'
SERVICES = ['sns']

_SCENARIO = "sns-filter-policy"


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A publish reaches only the subscription whose filter policy matches: the non-matching queue
    is empty once all four matching deliveries landed on the other, and widening its policy makes
    the same queue receive the next publish."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    a_url, a_arn = _create_queue_for_topic(ctx, topic_arn)
    b_url, b_arn = _create_queue_for_topic(ctx, topic_arn)

    sub_a = _subscribe_and_confirm(ctx, topic_arn, a_arn,
                                   attributes={"RawMessageDelivery": "true"})
    sub_b = _subscribe_and_confirm(ctx, topic_arn, b_arn,
                                   attributes={"RawMessageDelivery": "true"})
    _set_filter_policy(ctx, sub_a, {"kind": ["a"]})
    _set_filter_policy(ctx, sub_b, {"kind": ["b"]})

    sent_markers = [ctx.unique_name(f"sim2real-behav-sns-kind-a-{i}-") for i in range(4)]
    for marker in sent_markers:
        sns.publish(
            TopicArn=topic_arn, Message=marker,
            MessageAttributes={"kind": {"DataType": "String", "StringValue": "a"}},
        )

    # The barrier: every one of the four matching deliveries must land before the non-matching
    # queue is examined. Had the filter let them through, they would have taken the same trip.
    a_markers = _drain_until_all(ctx, a_url, sent_markers, timeout_s=120.0)
    assert len(a_markers) == 4, f"the barrier did not actually complete: {a_markers!r}"
    assert sorted(a_markers) == sorted(sent_markers), (
        f"the matching subscription lost messages: {sorted(set(sent_markers) - set(a_markers))!r}"
    )

    b_before = _receive_any(ctx, b_url, rounds=2, wait_s=20)
    assert b_before == [], (
        f"the non-matching subscription received a filtered-out message: {b_before!r}"
    )

    # Repair exactly the one broken thing and require the same queue to receive.
    _set_filter_policy(ctx, sub_b, {"kind": ["a"]})
    repaired_marker = ctx.unique_name("sim2real-behav-sns-repaired-")
    b_after = _publish_until_delivered(
        ctx, topic_arn, b_url, repaired_marker,
        attributes={"kind": {"DataType": "String", "StringValue": "a"}},
    )
    assert repaired_marker in b_after, (
        f"after the filter policy was widened the subscription still receives nothing: {b_after!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs = dict(attributes or {})
    if fifo:
        name = name + ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = name + ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
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


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
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


def _set_filter_policy(ctx, sub_arn: str, policy: dict, *, timeout_s: float = 60.0) -> None:
    """Set a FilterPolicy and poll until GetSubscriptionAttributes reads the same document back."""
    sns = ctx.client("sns")
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy", AttributeValue=json.dumps(policy))
    deadline = time.monotonic() + timeout_s
    got = None
    while time.monotonic() < deadline:
        raw = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("FilterPolicy")
        got = json.loads(raw) if raw else None
        if got == policy:
            return
        time.sleep(1.0)
    raise AssertionError(
        f"FilterPolicy on {sub_arn!r} read back as {got!r}, not {policy!r}, after {timeout_s}s"
    )


def _drain_until_all(ctx, queue_url: str, wanted: list[str], *,
                     timeout_s: float = 120.0) -> list[str]:
    """Long-poll the queue until every wanted marker has been seen; returns the markers collected."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body in outstanding:
                outstanding.discard(body)
                seen.append(body)
    if outstanding:
        raise AssertionError(
            f"the matching subscription never received {sorted(outstanding)!r} within {timeout_s}s; "
            f"it received {seen!r}"
        )
    return seen


def _receive_any(ctx, queue_url: str, *, rounds: int, wait_s: int) -> list[str]:
    """Long-poll a queue `rounds` times and return every body it produced (usually none)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


def _publish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str, *,
                             attributes: dict, attempts: int = 5) -> list[str]:
    """Publish the same marker up to `attempts` times, draining the queue between attempts.

    A SetSubscriptionAttributes(FilterPolicy) update is eventually consistent, so the bounded
    republish is the retry that makes the repaired-path assertion correct rather than racy; the
    marker itself is constant, so the assertion stays exact.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(attempts):
        sns.publish(TopicArn=topic_arn, Message=marker, MessageAttributes=attributes)
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                bodies.append(msg.get("Body", ""))
            if marker in bodies:
                return bodies
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
