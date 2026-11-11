"""message-attributes-survive-delivery-byte-for-byte."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "message-attributes-survive-delivery-byte-for-byte"
GROUP = 'server-side'
SERVICES = ['sns']

_SCENARIO = "sns-message-attributes"

# Every byte value, including NUL and the high half - the payload a UTF-8 round trip would corrupt.
_BINARY = bytes(range(256))
# SNS rejects a non-BMP codepoint in a String attribute despite the documented range, so this is
# the widest value it accepts: multi-byte BMP scripts, a combining mark and a Devanagari cluster.
_UNICODE = "sim2real é 日本語 क्ष"


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Binary, String and Number message attributes published to a topic arrive inside the SQS
    notification envelope with their exact types and values, including a binary value carrying every
    byte from 0x00 to 0xff.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    marker = ctx.unique_name("sim2real-behav-sns-attrs-")
    sns.publish(
        TopicArn=topic_arn,
        Message=marker,
        MessageAttributes={
            "bin": {"DataType": "Binary", "BinaryValue": _BINARY},
            "s": {"DataType": "String", "StringValue": _UNICODE},
            "n": {"DataType": "Number", "StringValue": "1.500"},
        },
    )

    envelope = json.loads(_await_body(ctx, queue_url, marker))
    attrs = envelope["MessageAttributes"]

    assert set(attrs) == {"bin", "s", "n"}, (
        f"the delivered attribute set is wrong: {sorted(attrs)!r}"
    )
    # The envelope carries a Binary attribute base64-encoded.
    decoded_bin = base64.b64decode(attrs["bin"]["Value"])
    first_diff = next(
        (i for i, (a, b) in enumerate(zip(decoded_bin, _BINARY)) if a != b), None)
    assert decoded_bin == _BINARY, (
        f"the binary attribute was corrupted in delivery: {len(decoded_bin)} bytes back of "
        f"{len(_BINARY)}, first differing index {first_diff!r}, head {decoded_bin[:16]!r}"
    )
    assert attrs["bin"]["Type"] == "Binary", (
        f"the binary attribute lost its type: {attrs['bin']!r}"
    )
    assert attrs["s"]["Value"] == _UNICODE, (
        f"the string attribute was mangled: {attrs['s']['Value']!r} != {_UNICODE!r}"
    )
    assert attrs["n"]["Type"] == "Number" and attrs["n"]["Value"] == "1.500", (
        f"the number attribute lost its representation: {attrs['n']!r}"
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
