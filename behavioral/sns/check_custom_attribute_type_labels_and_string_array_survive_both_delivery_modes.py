"""custom-attribute-type-labels-and-string-array-survive-both-delivery-modes."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-attribute-type-labels-and-string-array-survive-both-delivery-modes"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-custom-attribute-type-labels-and-string-"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Custom attribute type labels (Number.float, String.json, Binary.gif) and String.Array values,
    even a non-JSON String.Array, arrive verbatim in both the envelope and raw SQS delivery.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    env_url, env_arn = _create_queue_for_topic(ctx, topic_arn)
    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, env_arn)
    _subscribe_and_confirm(ctx, topic_arn, raw_arn, attributes={"RawMessageDelivery": "true"})

    marker = ctx.unique_name("sim2real-behav-sns-labels-")
    gif = b"GIF89a\x00\xff"
    published = {
        "price": ("Number.float", "3.14"),
        "doc": ("String.json", '{"a":1}'),
        "tags": ("String.Array", '["a",1,true,null]'),
        "loose": ("String.Array", "not-a-json-array"),
    }
    attrs = {k: {"DataType": t, "StringValue": v} for k, (t, v) in published.items()}
    attrs["icon"] = {"DataType": "Binary.gif", "BinaryValue": gif}
    resp = sns.publish(TopicArn=topic_arn, Message=marker, Subject="labels", MessageAttributes=attrs)
    assert resp.get("MessageId"), f"expected a MessageId for the labelled publish, got {resp!r}"

    env = _receive_keyed(ctx, env_url, _envelope_message, {marker}, timeout_s=90.0,
                         description="the enveloped subscriber receives the labelled publish")[marker]
    delivered = json.loads(env["Body"])["MessageAttributes"]
    expected_env = {k: {"Type": t, "Value": v} for k, (t, v) in published.items()}
    expected_env["icon"] = {"Type": "Binary.gif", "Value": base64.b64encode(gif).decode()}
    assert delivered == expected_env, (
        f"the envelope must carry every attribute with its declared label and verbatim value; "
        f"expected {expected_env!r}, got {delivered!r}"
    )

    raw = _receive_keyed(ctx, raw_url, lambda m: m["Body"], {marker}, timeout_s=90.0,
                         description="the raw subscriber receives the labelled publish")[marker]
    raw_attrs = raw.get("MessageAttributes", {})
    got_raw = {k: (v.get("DataType"), v.get("StringValue")) for k, v in raw_attrs.items()
               if k != "icon"}
    assert got_raw == published, (
        f"raw delivery must map each labelled attribute onto an SQS attribute with the same "
        f"DataType and value, and add nothing (no Subject); expected {published!r}, got {got_raw!r}"
    )
    icon = raw_attrs.get("icon", {})
    assert (icon.get("DataType"), bytes(icon.get("BinaryValue", b""))) == ("Binary.gif", gif), (
        f"the Binary.gif attribute must arrive raw as DataType 'Binary.gif' with its bytes; "
        f"got {icon!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(ctx, *, fifo: bool = False) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn

def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: _delete_queue_if_present(ctx, u))
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


def _delete_queue_if_present(ctx, url: str) -> None:
    """DeleteQueue; a queue the check itself already deleted is the one tolerated outcome."""
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

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
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s, interval_s=1.0,
        description="the sqs subscription leaves PendingConfirmation",
    )
    return sub_arn

def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value

def _receive_keyed(ctx, queue_url: str, key, wanted: set[str], *, timeout_s: float,
                   description: str) -> dict[str, dict]:
    """Long-poll until a message keyed `key(msg)` exists for every wanted key; RAISES on the
    deadline. Each message is returned whole (Body plus MessageAttributes)."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    other: list[str] = []
    deadline = time.monotonic() + timeout_s
    while not wanted <= set(got):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"], AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            k = key(msg)
            if k in wanted and k not in got:
                got[k] = msg
            else:
                other.append(msg["Body"][:160])
        if not wanted <= set(got) and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(wanted - set(got))!r} never arrived within "
                f"{timeout_s}s; other bodies seen: {other!r}")
    return got


def _envelope_message(msg: dict) -> str | None:
    """The Message field of an SNS notification envelope, or None for a non-envelope body."""
    try:
        body = json.loads(msg["Body"])
    except ValueError:
        return None
    if isinstance(body, dict) and body.get("Type") == "Notification":
        return body.get("Message")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
