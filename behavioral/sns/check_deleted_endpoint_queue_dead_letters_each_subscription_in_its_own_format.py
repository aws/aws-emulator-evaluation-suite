"""deleted-endpoint-queue-dead-letters-each-subscription-in-its-own-format."""
from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-endpoint-queue-dead-letters-each-subscription-in-its-own-format"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-deleted-endpoint-queue-dead-letters-each"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With the subscribed queue deleted, each redrive-enabled subscription dead-letters in its own
    format: the enveloped copy is the full notification naming its subscription, the raw copy is
    the bare body with SQS message attributes. A delivered publish is not dead-lettered.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    dlq_url, dlq_arn = _create_queue_for_topic(ctx, topic_arn)
    env_url, env_arn = _create_queue_for_topic(ctx, topic_arn)
    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    env_sub = _subscribe_and_confirm(ctx, topic_arn, env_arn)
    raw_sub = _subscribe_and_confirm(ctx, topic_arn, raw_arn,
                                     attributes={"RawMessageDelivery": "true"})
    for sub in (env_sub, raw_sub):
        _set_redrive(ctx, sub, dlq_arn)

    healthy = ctx.unique_name("sim2real-behav-sns-dlqdel-healthy-")
    sns.publish(TopicArn=topic_arn, Message=healthy)
    _receive_keyed(ctx, env_url, _envelope_message, {healthy}, timeout_s=60.0,
                   description="control: the enveloped endpoint receives while it exists")
    _receive_keyed(ctx, raw_url, lambda m: m["Body"], {healthy}, timeout_s=60.0,
                   description="control: the raw endpoint receives while it exists")
    early = _drain(ctx, dlq_url, window_s=15.0)
    assert early == [], f"a delivered message must not also be dead-lettered, got {early!r}"

    sqs.delete_queue(QueueUrl=env_url)
    sqs.delete_queue(QueueUrl=raw_url)

    attrs = {"n": {"DataType": "Number", "StringValue": "+5"}}
    # DeleteQueue propagates on SQS's side; republish (fresh marker each time) until one
    # publish has been dead-lettered by both subscriptions, then grade that one.
    for _ in range(6):
        dead = ctx.unique_name("sim2real-behav-sns-dlqdel-dead-")
        sns.publish(TopicArn=topic_arn, Message=dead, Subject="dead-letter", MessageAttributes=attrs)
        copies = _collect_keyed(ctx, dlq_url, _dlq_key, {f"env:{dead}", f"raw:{dead}"},
                                window_s=30.0)
        if {f"env:{dead}", f"raw:{dead}"} <= set(copies):
            break
    else:
        raise AssertionError(
            "no publish to the deleted endpoints was dead-lettered by both subscriptions "
            f"across 6 attempts; last attempt's DLQ keys {sorted(k[:60] for k in copies)!r}")

    envelope = json.loads(copies[f"env:{dead}"]["Body"])
    unsubscribe = parse_qs(urlparse(envelope["UnsubscribeURL"]).query).get("SubscriptionArn")
    assert unsubscribe == [env_sub], (
        f"the enveloped DLQ copy must name the subscription that failed in its UnsubscribeURL; "
        f"got {'the raw sibling' if unsubscribe == [raw_sub] else unsubscribe!r}"
    )
    got = (envelope["Type"], envelope["TopicArn"] == topic_arn, envelope.get("Subject"),
           envelope.get("MessageAttributes"))
    assert got == ("Notification", True, "dead-letter", {"n": {"Type": "Number", "Value": "+5"}}), (
        f"the enveloped DLQ copy must be the full notification with Subject and attributes "
        f"verbatim; got Type/TopicArn-matches/Subject/attributes {got!r}"
    )
    raw_copy = copies[f"raw:{dead}"]
    raw_attrs = {k: (v.get("DataType"), v.get("StringValue"))
                 for k, v in raw_copy.get("MessageAttributes", {}).items()}
    assert raw_attrs == {"n": ("Number", "5")}, (
        f"the raw DLQ copy must carry the attribute as an SQS Number attribute, got {raw_attrs!r}"
    )
    extra = [b for b in _drain(ctx, dlq_url, window_s=10.0) if dead in b]
    assert extra == [], f"each subscription dead-letters one copy, extra copies {extra!r}"



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
    """Bounded retry; raises on the deadline."""
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
    """(Error.Code, Error.Message) the call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

def _receive_keyed(ctx, queue_url: str, key, wanted: set[str], *, timeout_s: float,
                   description: str) -> dict[str, dict]:
    """Long-poll until a message keyed `key(msg)` exists for every wanted key; raises on the
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

def _set_redrive(ctx, sub_arn: str, dlq_arn: str) -> None:
    """Point the subscription's RedrivePolicy at the DLQ and wait for the read to agree."""
    sns = ctx.client("sns")
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
        AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("RedrivePolicy"),
        lambda raw: bool(raw) and json.loads(raw) == {"deadLetterTargetArn": dlq_arn},
        timeout_s=30.0, interval_s=1.0,
        description="GetSubscriptionAttributes reflects the RedrivePolicy")


def _collect_keyed(ctx, queue_url: str, key, wanted: set[str], *, window_s: float) -> dict:
    """Long-poll until every wanted key has arrived or the window ends; returns what arrived
    (possibly partial). The caller decides whether partial is a failure."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    deadline = time.monotonic() + window_s
    while not wanted <= set(got) and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"], AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            got.setdefault(key(msg), msg)
    return got


def _dlq_key(msg: dict) -> str:
    """'env:<Message>' for an enveloped copy, 'raw:<Body>' for a raw one."""
    inner = _envelope_message(msg)
    return f"env:{inner}" if inner is not None else f"raw:{msg['Body']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
