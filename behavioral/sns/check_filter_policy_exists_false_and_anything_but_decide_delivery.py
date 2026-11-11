"""filter-policy-exists-false-and-anything-but-decide-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "filter-policy-exists-false-and-anything-but-decide-delivery"
GROUP = "delivery"
SERVICES = ["sns"]

_SCENARIO = "sns-filter-polarity"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Over four messages, `exists: false` delivers exactly those without a coupon attribute and
    list `anything-but` exactly those whose channel is not listed; flipping to `exists: true`
    then delivers the withheld coupon-bearing message.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)

    control_url, control_arn = _create_queue_for_topic(ctx, topic_arn)
    exists_url, exists_arn = _create_queue_for_topic(ctx, topic_arn)
    ab_url, ab_arn = _create_queue_for_topic(ctx, topic_arn)

    _subscribe_and_confirm(ctx, topic_arn, control_arn,
                           attributes={"RawMessageDelivery": "true"})
    exists_sub = _subscribe_and_confirm(
        ctx, topic_arn, exists_arn,
        attributes={"RawMessageDelivery": "true",
                    "FilterPolicy": json.dumps({"coupon": [{"exists": False}]})},
    )
    _subscribe_and_confirm(
        ctx, topic_arn, ab_arn,
        attributes={"RawMessageDelivery": "true",
                    "FilterPolicy": json.dumps(
                        {"channel": [{"anything-but": ["fax", "pager"]}]})},
    )

    m1 = ctx.unique_name("sim2real-behav-polarity-nocoupon-sms-")
    m2 = ctx.unique_name("sim2real-behav-polarity-coupon-sms-")
    m3 = ctx.unique_name("sim2real-behav-polarity-nocoupon-fax-")
    m4 = ctx.unique_name("sim2real-behav-polarity-coupon-fax-")
    matrix = [
        (m1, {"channel": _s("sms")}),
        (m2, {"channel": _s("sms"), "coupon": _s("SAVE10")}),
        (m3, {"channel": _s("fax")}),
        (m4, {"channel": _s("fax"), "coupon": _s("SAVE10")}),
    ]

    started = time.monotonic()
    for marker, attributes in matrix:
        sns.publish(TopicArn=topic_arn, Message=marker, MessageAttributes=attributes)

    # ---- barrier: all four complete the trip on the unfiltered twin -----------------------
    control_seen = _await_bodies(
        ctx, control_url, {m1, m2, m3, m4}, timeout_s=120.0,
        description=("the unfiltered twin must receive all four messages; without this barrier "
                     "an absence at either filtered arm proves nothing"),
    )
    latency = max(max(control_seen.values()) - started, 1.0)
    filtered_ceiling = max(60.0, 3.0 * latency + 20.0)

    # ---- the exists:false arm: exactly {M1, M3} -------------------------------------------
    _await_bodies(
        ctx, exists_url, {m1, m3}, timeout_s=filtered_ceiling,
        description=("{\"coupon\": [{\"exists\": false}]} must deliver exactly the two "
                     "messages that carry no coupon attribute"),
        forbidden={m2, m4},
    )

    # ---- the anything-but arm: exactly {M1, M2} -------------------------------------------
    _await_bodies(
        ctx, ab_url, {m1, m2}, timeout_s=filtered_ceiling,
        description=("{\"channel\": [{\"anything-but\": [\"fax\", \"pager\"]}]} must "
                     "deliver exactly the two messages whose channel is neither"),
        forbidden={m3, m4},
    )

    # ---- both absences held over one window calibrated from the measured latency ----------
    window = max(3.0 * latency, 15.0)
    leaked = _drain_both(ctx, {"exists:false arm": exists_url, "anything-but arm": ab_url},
                         window_s=window)
    assert leaked == {"exists:false arm": [], "anything-but arm": []}, (
        f"after both arms had received their matching messages, a {window:.0f}s window "
        f"(>=3x the measured control latency of {latency:.1f}s) must yield nothing more; got "
        f"{leaked!r} — a non-empty list here is a withheld message arriving late, which is "
        "over-delivery, not slowness"
    )
    for label, url in (("exists:false", exists_url), ("anything-but", ab_url)):
        approx = int(sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"])
        assert approx == 0, (
            "second independent observable for the absence: expected "
            f"ApproximateNumberOfMessages == 0 on the {label} queue, got {approx}"
        )

    # ---- repair exactly one thing: flip the polarity and DEMAND the withheld message ------
    _set_filter_policy(ctx, exists_sub, {"coupon": [{"exists": True}]})
    _republish_until_delivered(
        ctx, topic_arn, exists_url, m2, dict(matrix[1][1]),
        attempts=3, per_attempt_s=max(30.0, 2.0 * latency),
        description=("after exists is flipped from false to true, the identical "
                     "coupon-bearing message must be delivered to the same subscription — "
                     "this is what proves the operator was evaluated rather than the "
                     "subscription being broken"),
    )

    stored = json.loads(sns.get_subscription_attributes(
        SubscriptionArn=exists_sub)["Attributes"]["FilterPolicy"])
    assert stored == {"coupon": [{"exists": True}]}, (
        f"expected the flipped policy to be the stored document, got {stored!r}"
    )


def _s(value: str) -> dict:
    """A single String-typed message attribute value."""
    return {"DataType": "String", "StringValue": value}


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


def _drain_both(ctx, queues: dict[str, str], *, window_s: float) -> dict[str, list[str]]:
    """Alternate long polls across several queues for one shared window; return the bodies."""
    sqs = ctx.client("sqs")
    out: dict[str, list[str]] = {label: [] for label in queues}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for label, url in queues.items():
            resp = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                out[label].append(msg["Body"])
    return out


def _republish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str,
                               attributes: dict, *, attempts: int, per_attempt_s: float,
                               description: str) -> None:
    """Publish the same marker up to `attempts` times and RAISE if it never lands.

    A FilterPolicy update is eventually consistent on the delivery path, hence the retries."""
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

    Returns {body: monotonic time first seen} so callers can calibrate an absence window.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
