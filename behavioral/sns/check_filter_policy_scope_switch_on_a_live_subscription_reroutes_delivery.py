"""filter-policy-scope-switch-on-a-live-subscription-reroutes-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-scope-switch-on-a-live-subscription-reroutes-delivery"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-filter-policy-scope-switch-on-a-live-sub"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Switching only FilterPolicyScope on a live subscription re-points its unchanged policy:
    under MessageAttributes the attribute match is delivered and the body match withheld, and
    after switching to MessageBody the reverse holds.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    twin_url, twin_arn = _create_queue_for_topic(ctx, topic_arn)
    url, arn = _create_queue_for_topic(ctx, topic_arn)
    raw = {"RawMessageDelivery": "true"}
    _subscribe_and_confirm(ctx, topic_arn, twin_arn, attributes=raw)
    sub = _subscribe_and_confirm(
        ctx, topic_arn, arn, attributes=dict(raw, FilterPolicy=json.dumps({"kind": ["wanted"]})))

    def publish_pair(tag: str) -> tuple[str, str]:
        by_attr = json.dumps({"kind": "unwanted", "id": ctx.unique_name(f"sim2real-attr-{tag}-")})
        by_body = json.dumps({"kind": "wanted", "id": ctx.unique_name(f"sim2real-body-{tag}-")})
        sns.publish(TopicArn=topic_arn, Message=by_attr, MessageAttributes={
            "kind": {"DataType": "String", "StringValue": "wanted"}})
        sns.publish(TopicArn=topic_arn, Message=by_body)
        return by_attr, by_body

    def one_side(tag: str, admit_body: bool):
        # The unfiltered twin bounds each absence by a delivery of the same publish.
        by_attr, by_body = publish_pair(tag)
        _receive_keyed(ctx, twin_url, lambda m: m["Body"], {by_attr, by_body}, timeout_s=60.0,
                       description="the unfiltered twin receives both messages")
        admitted, withheld = (by_body, by_attr) if admit_body else (by_attr, by_body)
        # Bodies read alongside the match count as leaks too, not only the later drain.
        other: list[str] = []
        _receive_keyed(ctx, url, lambda m: m["Body"], {admitted}, timeout_s=60.0,
                       description="the filtered subscription receives its match", other=other)
        return withheld, other + _drain(ctx, url, window_s=15.0)

    withheld, leaked = one_side("attrscope", admit_body=False)
    assert leaked == [], (
        f"under MessageAttributes scope the body-only match must be withheld; got {leaked!r}"
    )

    sns.set_subscription_attributes(SubscriptionArn=sub, AttributeName="FilterPolicyScope",
                                    AttributeValue="MessageBody")
    stored = _poll_until(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"],
        lambda a: a.get("FilterPolicyScope") == "MessageBody", timeout_s=30.0, interval_s=1.0,
        description="the subscription reports FilterPolicyScope=MessageBody")
    assert json.loads(stored["FilterPolicy"]) == {"kind": ["wanted"]}, (
        f"switching the scope must leave the policy unchanged, got {stored['FilterPolicy']!r}"
    )

    # The switch is eventually consistent on the delivery path: wait until a body match is
    # admitted, then grade a fresh pair.
    for attempt in range(6):
        by_attr, by_body = publish_pair(f"converge{attempt}")
        _receive_keyed(ctx, twin_url, lambda m: m["Body"], {by_attr, by_body}, timeout_s=60.0,
                       description="the unfiltered twin receives both messages")
        if by_body in _drain(ctx, url, window_s=10.0):
            break
    else:
        raise AssertionError("after the scope switch the body match was never admitted")
    _drain(ctx, url, window_s=5.0)

    withheld, leaked = one_side("bodyscope", admit_body=True)
    assert leaked == [], (
        f"under MessageBody scope the attribute-only match must be withheld; got {leaked!r}"
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

def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

def _receive_keyed(ctx, queue_url: str, key, wanted: set[str], *, timeout_s: float,
                   description: str, other: list[str] | None = None) -> dict[str, dict]:
    """Long-poll until a message keyed `key(msg)` exists for every wanted key; RAISES on the
    deadline. Each message is returned whole (Body plus MessageAttributes). Bodies outside
    `wanted` are appended to the caller-supplied `other` list when one is given."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    if other is None:
        other = []
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
