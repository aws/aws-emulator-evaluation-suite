"""raw-message-delivery-strips-the-envelope-for-only-that-subscription."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "raw-message-delivery-strips-the-envelope-for-only-that-subscription"
GROUP = 'delivery'
SERVICES = ['sns']

_SCENARIO = "sns-raw-delivery"


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """One publish to a topic with two SQS subscriptions delivers the bare body to the
    RawMessageDelivery=true subscription and the full JSON envelope to the other."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    wrapped_url, wrapped_arn = _create_queue_for_topic(ctx, topic_arn)

    raw_sub = _subscribe_and_confirm(ctx, topic_arn, raw_arn,
                                     attributes={"RawMessageDelivery": "true"})
    wrapped_sub = _subscribe_and_confirm(ctx, topic_arn, wrapped_arn)
    _await_attribute(ctx, raw_sub, "RawMessageDelivery", "true")

    wrapped_attrs = sns.get_subscription_attributes(SubscriptionArn=wrapped_sub)["Attributes"]
    assert wrapped_attrs.get("RawMessageDelivery", "false") == "false", (
        "the control subscription must not have RawMessageDelivery set, else the differential "
        f"proves nothing: {wrapped_attrs.get('RawMessageDelivery')!r}"
    )

    payload = ctx.unique_name("sim2real-behav-sns-rawpay-")
    message_id = sns.publish(TopicArn=topic_arn, Message=payload)["MessageId"]

    raw_body = _await_body(ctx, raw_url, payload)
    wrapped_body = _await_body(ctx, wrapped_url, payload)

    assert raw_body == payload, (
        f"RawMessageDelivery still wrapped the message: {raw_body[:200]!r}"
    )
    envelope = json.loads(wrapped_body)
    assert envelope["Message"] == payload, (
        f"the enveloped subscription did not carry the message: {wrapped_body[:200]!r}"
    )
    assert wrapped_body != raw_body, (
        "both subscriptions delivered the same payload, so RawMessageDelivery had no effect"
    )
    assert envelope["MessageId"] == message_id, (
        f"envelope MessageId {envelope['MessageId']!r} != Publish MessageId {message_id!r}"
    )
    assert envelope["Type"] == "Notification", (
        f"the non-raw subscription must receive a Notification envelope: {wrapped_body[:200]!r}"
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


def _await_attribute(ctx, sub_arn: str, name: str, want: str, *, timeout_s: float = 60.0) -> None:
    """Poll GetSubscriptionAttributes until the named attribute reads back as want."""
    sns = ctx.client("sns")
    deadline = time.monotonic() + timeout_s
    got = None
    while time.monotonic() < deadline:
        got = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get(name)
        if got == want:
            return
        time.sleep(1.0)
    raise AssertionError(
        f"{name} on {sub_arn!r} was {got!r}, not {want!r}, after {timeout_s}s"
    )


def _await_body(ctx, queue_url: str, needle: str, *, timeout_s: float = 90.0) -> str:
    """Long-poll the queue until a body containing needle arrives; returns that body."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            seen.append(body)
            if needle in body:
                return body
    raise AssertionError(
        f"no message containing {needle!r} was delivered within {timeout_s}s; "
        f"bodies seen: {[b[:120] for b in seen]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
