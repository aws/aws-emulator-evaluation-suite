"""publish-of-exactly-256-kib-delivered-intact-and-one-byte-more-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-of-exactly-256-kib-delivered-intact-and-one-byte-more-rejected"
GROUP = "validation"
SERVICES = ["sns"]

_SCENARIO = "sns-publish-of-exactly-256-kib-delivered-int"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Publish accepts exactly 262144 UTF-8 bytes and delivers them intact to raw and enveloped
    subscribers, but refuses 262145; with a 3-byte character, 87381 characters are accepted and
    delivered while 87382 are refused, so the limit is counted in bytes, not characters."""
    sns = ctx.client("sns")
    limit = 262144
    topic_arn = _create_topic(ctx)
    env_url, env_arn = _create_queue_for_topic(ctx, topic_arn)
    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, env_arn)
    _subscribe_and_confirm(ctx, topic_arn, raw_arn, attributes={"RawMessageDelivery": "true"})

    wide = "\u65e5"
    for body in ("r" * (limit + 1), wide * (limit // 3 + 1)):
        code, message = _error(lambda b=body: sns.publish(TopicArn=topic_arn, Message=b))
        assert (code, message) == ("InvalidParameter", "Invalid parameter: Message too long"), (
            f"a {len(body)}-character, {len(body.encode())}-byte body must be refused with "
            f"InvalidParameter 'Invalid parameter: Message too long', got {code!r} {message!r}"
        )

    ascii_max = "a" * limit
    wide_max = wide * (limit // 3)
    sizes = (len(ascii_max.encode()), len(wide_max.encode()))
    assert sizes == (limit, limit - 1), f"test-data construction error: sizes {sizes!r}"
    for body in (ascii_max, wide_max):
        resp = sns.publish(TopicArn=topic_arn, Message=body)
        assert resp.get("MessageId"), (
            f"a {len(body.encode())}-byte body is within the limit and must be accepted, got "
            f"{resp!r}"
        )

    by_size = lambda m: str(len(m["Body"].encode()))
    raw = _receive_keyed(ctx, raw_url, by_size, {str(limit), str(limit - 1)}, timeout_s=120.0,
                         description="the raw subscriber receives both maximum-size bodies")
    assert raw[str(limit)]["Body"] == ascii_max, (
        "the 262144-byte ASCII body must reach the raw subscriber byte-for-byte")
    assert raw[str(limit - 1)]["Body"] == wide_max, (
        "the 262143-byte three-byte-character body must reach the raw subscriber intact")

    env = _receive_keyed(ctx, env_url, lambda m: str(len((_envelope_message(m) or "").encode())),
                         {str(limit), str(limit - 1)}, timeout_s=120.0,
                         description="the enveloped subscriber receives both maximum-size bodies")
    for size, body in ((str(limit), ascii_max), (str(limit - 1), wide_max)):
        envelope_bytes = len(env[size]["Body"].encode())
        assert _envelope_message(env[size]) == body and envelope_bytes > limit, (
            f"the {size}-byte body must arrive intact inside an envelope larger than the publish "
            f"limit; envelope was {envelope_bytes} bytes"
        )
    leaked = [len(b) for b in _drain(ctx, raw_url, window_s=10.0)]
    assert leaked == [], f"a refused publish must deliver nothing, got bodies of length {leaked!r}"


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

def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

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

def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert on
    leakage rather than discard it."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"][:300])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
