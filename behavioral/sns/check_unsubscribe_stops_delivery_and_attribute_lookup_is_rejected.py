"""unsubscribe-stops-delivery-and-attribute-lookup-is-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "unsubscribe-stops-delivery-and-attribute-lookup-is-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-unsubscribe"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """After Unsubscribe, GetSubscriptionAttributes on that ARN is rejected with NotFound and the
    queue receives nothing further, while a second subscription on the same topic keeps receiving
    every publish.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    a_url, a_arn = _create_queue_for_topic(ctx, topic_arn)
    b_url, b_arn = _create_queue_for_topic(ctx, topic_arn)
    sub_a = _subscribe_and_confirm(ctx, topic_arn, a_arn,
                                   attributes={"RawMessageDelivery": "true"})
    sub_b = _subscribe_and_confirm(ctx, topic_arn, b_arn,
                                   attributes={"RawMessageDelivery": "true"})

    baseline = ctx.unique_name("sim2real-behav-sns-baseline-")
    sns.publish(TopicArn=topic_arn, Message=baseline)
    a_baseline = _drain_until_all(ctx, a_url, [baseline], timeout_s=90.0)
    b_baseline = _drain_until_all(ctx, b_url, [baseline], timeout_s=90.0)
    assert a_baseline == [baseline], (
        f"queue A never received anything even before the unsubscribe: {a_baseline!r}"
    )
    assert b_baseline == [baseline], (
        f"queue B never received the baseline, so it cannot serve as the control: {b_baseline!r}"
    )

    sns.unsubscribe(SubscriptionArn=sub_a)
    listed = _await_subscription_gone(ctx, topic_arn, sub_a)
    assert sub_a not in [s["SubscriptionArn"] for s in listed], (
        f"the removed subscription is still listed: {[s['SubscriptionArn'] for s in listed]!r}"
    )
    assert sub_b in [s["SubscriptionArn"] for s in listed], (
        f"Unsubscribe removed the wrong subscription; {sub_b!r} is missing from "
        f"{[s['SubscriptionArn'] for s in listed]!r}"
    )

    post_markers = [ctx.unique_name(f"sim2real-behav-sns-post-{i}-") for i in range(3)]
    for marker in post_markers:
        sns.publish(TopicArn=topic_arn, Message=marker)

    # B must receive all three before A is examined, so A's silence is evidence, not latency.
    b_after = _drain_until_all(ctx, b_url, post_markers, timeout_s=120.0)
    assert sorted(b_after) == sorted(post_markers), (
        f"the surviving subscription lost messages, so the absence below is not evidence: "
        f"{b_after!r}"
    )
    a_after = _receive_any(ctx, a_url, rounds=2, wait_s=20)
    assert a_after == [], f"the unsubscribed queue kept receiving: {a_after!r}"

    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_a))
    assert code == "NotFound", (
        f"GetSubscriptionAttributes on a removed subscription was not rejected: {code!r}"
    )
    assert message == "Subscription does not exist", (
        f"GetSubscriptionAttributes on a removed subscription carried the wrong message: "
        f"{message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(). Raises if fn SUCCEEDS — an unexpected success
    is the strongest possible signal."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
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
    ctx.on_cleanup(lambda s=sub_arn: _best_effort_unsubscribe(ctx, s))
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


def _best_effort_unsubscribe(ctx, sub_arn: str) -> None:
    """Unsubscribe, tolerating NotFound for the subscription this check removes on purpose."""
    from botocore.exceptions import ClientError
    try:
        ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFound":
            raise


def _list_subscriptions(ctx, topic_arn: str) -> list[dict]:
    """Every subscription on the topic, paginated — page one is not the full set."""
    sns = ctx.client("sns")
    out: list[dict] = []
    paginator = sns.get_paginator("list_subscriptions_by_topic")
    for page in paginator.paginate(TopicArn=topic_arn):
        out.extend(page.get("Subscriptions", []))
    return out


def _await_subscription_gone(ctx, topic_arn: str, sub_arn: str, *,
                             timeout_s: float = 60.0) -> list[dict]:
    """Poll ListSubscriptionsByTopic until sub_arn is absent; returns the final listing.
    Delivery absence is only meaningful once the control plane agrees the subscription is gone."""
    deadline = time.monotonic() + timeout_s
    listed: list[dict] = []
    while time.monotonic() < deadline:
        listed = _list_subscriptions(ctx, topic_arn)
        if sub_arn not in [s["SubscriptionArn"] for s in listed]:
            return listed
        time.sleep(1.0)
    raise AssertionError(
        f"{sub_arn!r} was still listed on {topic_arn!r} {timeout_s}s after Unsubscribe: "
        f"{[s['SubscriptionArn'] for s in listed]!r}"
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
            f"{sorted(outstanding)!r} never arrived within {timeout_s}s; received {seen!r}"
        )
    return seen


def _receive_any(ctx, queue_url: str, *, rounds: int, wait_s: int) -> list[str]:
    """Long-poll a queue `rounds` times and return every body it produced (expected: none)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
