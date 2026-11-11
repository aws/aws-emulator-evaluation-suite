"""sns-to-sqs-envelope-carries-the-subject-and-typed-message-attributes."""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-to-sqs-envelope-carries-the-subject-and-typed-message-attributes"

GROUP = "event-propagation"

SERVICES = ["sns", "sqs"]

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _allow_topic(ctx, queue: dict, topic_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )


def _envelope_id(raw: str):
    """The SNS envelope MessageId of a raw SQS body, or None for a body that is no envelope."""
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    return body.get("MessageId") if isinstance(body, dict) else None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Publish with a Subject, a multibyte JSON-looking message and String, Number and Binary
    attributes reaches the subscribed queue as one envelope carrying all of them exactly, with the
    Publish MessageId, SignatureVersion 1, a millisecond timestamp and this subscription's unsubscribe URL.
    """
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    _allow_topic(ctx, queue, topic["arn"])
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"], ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(
        _tolerant(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn), "NotFound")
    )

    marker = ctx.unique_name("marker-")
    message = json.dumps({"marker": marker, "text": "Grüße 中文 \U0001f4e6"}, ensure_ascii=False)
    subject = "Order shipped: #42 (ünïcode)"
    blob = bytes(range(0, 256, 17))
    published = sns.publish(
        TopicArn=topic["arn"],
        Message=message,
        Subject=subject,
        MessageAttributes={
            "tenant": {"DataType": "String", "StringValue": "Example Corp"},
            "qty": {"DataType": "Number", "StringValue": "7.25"},
            "blob": {"DataType": "Binary", "BinaryValue": blob},
        },
    )
    messages = _wait_for_messages(ctx, queue["url"], expected_count=1, timeout_s=40.0)
    # Delivery is at least once: a repeat of this Publish's envelope is allowed, any other message
    # is a stray.
    later = (
        ctx.client("sqs")
        .receive_message(QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        .get("Messages", [])
    )
    strays = [m["Body"] for m in later if _envelope_id(m["Body"]) != published["MessageId"]]
    assert not strays, f"one Publish also delivered other messages to the queue: {strays!r:.300}"
    envelope = messages[0]["body"]
    assert isinstance(envelope, dict), (
        f"expected an SNS envelope object, got {type(envelope).__name__}"
    )
    want = {
        "Type": "Notification",
        "MessageId": published["MessageId"],
        "TopicArn": topic["arn"],
        "Subject": subject,
        "Message": message,
        "SignatureVersion": "1",
    }
    got = {k: envelope.get(k) for k in want}
    assert got == want, f"envelope fields {got!r}, expected {want!r}"
    want_attrs = {
        "tenant": {"Type": "String", "Value": "Example Corp"},
        "qty": {"Type": "Number", "Value": "7.25"},
        "blob": {"Type": "Binary", "Value": base64.b64encode(blob).decode()},
    }
    assert envelope.get("MessageAttributes") == want_attrs, (
        f"envelope MessageAttributes {envelope.get('MessageAttributes')!r}, expected {want_attrs!r}"
    )
    assert _TIMESTAMP.match(envelope.get("Timestamp", "")), (
        f"envelope Timestamp {envelope.get('Timestamp')!r} is not ISO 8601 UTC with milliseconds"
    )
    unsubscribe = envelope.get("UnsubscribeURL", "")
    assert unsubscribe.endswith(f"/?Action=Unsubscribe&SubscriptionArn={sub_arn}"), (
        "envelope UnsubscribeURL does not end with this subscription's Unsubscribe action"
    )
    # The message attributes ride inside the envelope body, not as SQS message attributes.
    assert messages[0]["attributes"] == {}, (
        f"non-raw delivery set SQS message attributes {sorted(messages[0]['attributes'])}, expected none"
    )
    _gone_subscription(ctx, sub_arn, topic["arn"])
    _gone_topic(ctx, topic["arn"])
    _gone_queue(ctx, queue["name"], queue["url"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return {"name": name, "arn": arn}


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=40.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 40.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, with exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message: str, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: still readable {timeout_s:.0f}s after the delete; last answer {last!r:.300}"
            )
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_NF_MSG = "The specified queue does not exist."


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # A deleted queue can keep answering for a while, so the read is polled.
    _poll_refused(
        lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG
    )
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"),
        _SQS_NF,
        400,
        f"SendMessage {name}",
        _SQS_NF_MSG,
    )


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(
        lambda: sns.get_topic_attributes(TopicArn=arn),
        nf,
        404,
        "GetTopicAttributes",
        "Topic does not exist",
    )
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the deleted topic"
    _refused(
        lambda: sns.publish(TopicArn=arn, Message="gone"),
        nf,
        404,
        "Publish to deleted topic",
        "Topic does not exist",
    )


def _gone_subscription(ctx, sub_arn: str, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sns.unsubscribe(SubscriptionArn=sub_arn)
    nf = ("NotFound",)
    _poll_refused(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn),
        nf,
        404,
        "GetSubscriptionAttributes",
        "Subscription does not exist",
    )
    listed = {
        s["SubscriptionArn"]
        for s in _paged(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)
    }
    assert sub_arn not in listed, "ListSubscriptionsByTopic still lists the removed subscription"
    _refused(
        lambda: sns.set_subscription_attributes(
            SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"
        ),
        nf,
        404,
        "SetSubscriptionAttributes on removed subscription",
        "Subscription does not exist",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
