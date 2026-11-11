"""filter-policy-numeric-operator-boundary-decides-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "filter-policy-numeric-operator-boundary-decides-delivery"
GROUP = "delivery"
SERVICES = ["sns"]

_SCENARIO = "sns-filter-numeric"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With `{"price": [{"numeric": [">", 100]}]}` price=101 is delivered and price=100 is withheld
    while an unfiltered twin receives both, and widening the operator to `>=` makes the previously
    withheld subscription receive: the numeric operator decides delivery at the exact boundary.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)

    control_url, control_arn = _create_queue_for_topic(ctx, topic_arn)
    filtered_url, filtered_arn = _create_queue_for_topic(ctx, topic_arn)

    # The control arm carries NO filter policy: it is the twin doing the same work at the same
    # moment, and it is what makes an absence at the filtered arm mean "withheld" rather than
    # "nothing was ever published".
    _subscribe_and_confirm(ctx, topic_arn, control_arn,
                           attributes={"RawMessageDelivery": "true"})
    filtered_sub = _subscribe_and_confirm(
        ctx, topic_arn, filtered_arn,
        attributes={"RawMessageDelivery": "true",
                    "FilterPolicy": json.dumps({"price": [{"numeric": [">", 100]}]})},
    )

    at_boundary = ctx.unique_name("sim2real-behav-numeric-at-100-")
    above = ctx.unique_name("sim2real-behav-numeric-at-101-")

    # Published boundary-first, so in-order delivery would surface the withheld message before
    # the delivered one at the filtered arm.
    started = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=at_boundary,
                MessageAttributes=_number("price", "100"))
    sns.publish(TopicArn=topic_arn, Message=above,
                MessageAttributes=_number("price", "101"))

    # ---- barrier: both messages complete the trip on the unfiltered twin ------------------
    control_seen = _await_bodies(
        ctx, control_url, {at_boundary, above}, timeout_s=120.0,
        description=("the unfiltered twin subscription must receive BOTH messages; without "
                     "this barrier an absence at the filtered arm proves nothing"),
    )
    latency = max(max(control_seen.values()) - started, 1.0)

    # ---- the delivered half, with the withheld half a hard failure if it appears ----------
    _await_bodies(
        ctx, filtered_url, {above}, timeout_s=max(120.0, 3.0 * latency + 30.0),
        description=("price=101 must satisfy {\"numeric\": [\">\", 100]} and be delivered"),
        forbidden={at_boundary},
    )

    # ---- the withheld half, over a window calibrated from the measured control latency ----
    window = max(3.0 * latency, 15.0)
    leaked = _drain(ctx, filtered_url, window_s=window)
    assert leaked == [], (
        f"price=100 must NOT satisfy {{\"numeric\": [\">\", 100]}}: the filtered subscription "
        f"received {leaked!r} during a {window:.0f}s window (>=3x the measured control latency "
        f"of {latency:.1f}s) that began after price=101 had already arrived"
    )
    approx = int(sqs.get_queue_attributes(
        QueueUrl=filtered_url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"]["ApproximateNumberOfMessages"])
    assert approx == 0, (
        "second independent observable for the absence: expected ApproximateNumberOfMessages "
        f"== 0 on the filtered queue, got {approx}"
    )

    # ---- repair exactly the one withheld thing and DEMAND the delivery -------------------
    _set_filter_policy(ctx, filtered_sub, {"price": [{"numeric": [">=", 100]}]})
    _republish_until_delivered(
        ctx, topic_arn, filtered_url, at_boundary, _number("price", "100"),
        attempts=5, per_attempt_s=max(30.0, 2.0 * latency),
        description=("after the operator is widened from > to >=, the identical price=100 "
                     "message must be delivered to the same subscription — this is what "
                     "proves the boundary was the discriminator rather than the numeric "
                     "operator suppressing everything"),
    )

    # ---- independent read of the control document, through a different operation ----------
    stored = json.loads(sns.get_subscription_attributes(
        SubscriptionArn=filtered_sub)["Attributes"]["FilterPolicy"])
    assert stored == {"price": [{"numeric": [">=", 100]}]}, (
        f"expected the widened policy to be the stored document, got {stored!r}"
    )


# ===== helpers =====


def _number(name: str, value: str) -> dict:
    """A single Number-typed message attribute. SNS compares `numeric` policy operators only
    against Number attributes (documented in Filter policy constraints in Amazon SNS)."""
    return {name: {"DataType": "Number", "StringValue": value}}


def _set_filter_policy(ctx, sub_arn: str, policy: dict, *, timeout_s: float = 60.0) -> None:
    """Replace a subscription's FilterPolicy and poll until an independent read matches."""
    sns = ctx.client("sns")
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy",
        AttributeValue=json.dumps(policy))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("FilterPolicy"),
        lambda raw: bool(raw) and json.loads(raw) == policy,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"GetSubscriptionAttributes reflects the FilterPolicy {policy!r}",
    )


def _republish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str,
                               attributes: dict, *, attempts: int, per_attempt_s: float,
                               description: str) -> None:
    """Publish the same marker up to `attempts` times, draining between attempts, and RAISE
    if it never lands.

    A FilterPolicy update is eventually consistent on the delivery path, so the bounded
    republish is the retry that makes the repaired-path assertion correct rather than racy.
    The marker and its attributes are constant across attempts, so the assertion stays exact.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    seen: list[str] = []
    for _ in range(attempts):
        sns.publish(TopicArn=topic_arn, Message=marker, MessageAttributes=attributes)
        deadline = time.monotonic() + per_attempt_s
        while time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                seen.append(msg["Body"])
            if marker in seen:
                return
    raise AssertionError(
        f"{description}: {marker!r} was never delivered across {attempts} republishes of "
        f"{per_attempt_s:.0f}s each; bodies seen: {seen!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(
        Name=name, Attributes=dict(attributes or {}), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    url = sqs.create_queue(
        QueueName=name,
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
    """Long-poll until every wanted body is seen; RAISES on the deadline.

    Returns {body: monotonic time it was first seen} so a caller can measure the real
    latency of this wiring and calibrate an absence window from it. A body in `forbidden`
    that arrives raises immediately: it is a leak, and swallowing it would hide the very
    thing the caller is about to assert.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        # The empty default only ever means "poll again"; the deadline below RAISES, so an
        # absence can never pass.
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
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert
    on leakage rather than discard it. The empty default is correct here: it feeds an
    equality-to-empty assertion."""
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
