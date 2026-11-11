"""notifications-filtered-out-and-delivered-are-two-sided-for-complementary-subscriptions."""

# WHY IT DISCRIMINATES. `NumberOfNotificationsFilteredOut` is the metric that separates
# "correctly filtered out" from "never sent": without it, silently dropping a message and
# correctly evaluating a filter policy both leave the queue empty. This file demands the pair, in
# both directions, from a single fresh topic whose lifetime counters are therefore exact.
#
# What the check relies on:
#   - For a topic with TWO subscriptions carrying complementary filter policies, ONE publish that
#     matches exactly one of them yields, over the publish window and dimension TopicName:
#     NumberOfMessagesPublished == 1, NumberOfNotificationsDelivered == 1,
#     NumberOfNotificationsFilteredOut == 1 ("A filter policy rejects a message when the message
#     attributes don't match"; "If the subscription rejects the message, the delivery attempt isn't
#     counted for [Delivered]"); filtered-out is counted PER SUBSCRIPTION.
#   - `NumberOfNotificationsFilteredOut-MessageAttributes` carries the same count as the aggregate
#     metric when the policy's scope is MessageAttributes (the default). Asserted only as ">= 1 and
#     <= the aggregate", since AWS documents the sub-metrics without stating they partition.
#   - AWS/SNS metric visibility is under 300s. AWS publishes no bound.
#   - SNS -> SQS delivery latency L is seconds; the absence window is 3x the MEASURED L, floored at
#     30s, never a constant.
#   - A fresh topic has no prior traffic, so lifetime sums over the check's own window are exact;
#     the topic name is `ctx.unique_name`d so no retained data for a recycled name can drift them.
#   - Worst ~500s, typical ~150s; CloudWatch visibility dominates. Teardown: one topic, two
#     subscriptions, two queues -- inside a 60s cleanup budget.
# Docs: https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html (the AWS/SNS
# metric table, the TopicName dimension, Sum statistic, and the definitions quoted above);
# https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html.

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "notifications-filtered-out-and-delivered-are-two-sided-for-complementary-subscriptions"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "sns", "sqs"]


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, topic_arn, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowSns",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Receive and delete every message that arrives within `seconds`; return the parsed bodies."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _sns_metric(ctx, metric, topic_name, *, since):
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/SNS",
        MetricName=metric,
        Dimensions=[{"Name": "TopicName", "Value": topic_name}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints", [])
    return sum(p["Sum"] for p in points)


def _subscribe(ctx, topic_arn, queue_arn, filter_policy, check_tag):
    sns = ctx.client("sns")
    arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"FilterPolicy": json.dumps(filter_policy), "RawMessageDelivery": "false"},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").unsubscribe(SubscriptionArn=a))
    stored = sns.get_subscription_attributes(SubscriptionArn=arn)["Attributes"]
    assert json.loads(stored["FilterPolicy"]) == filter_policy, (
        f"the stored FilterPolicy for {arn} is {stored.get('FilterPolicy')!r}, expected "
        f"{json.dumps(filter_policy)!r} — a policy that did not stick makes every filtering claim "
        f"below vacuous"
    )
    return arn


# ===== the check =====
# timing:real-time — metric: 60 s https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html
@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A publish that matches one of two complementary subscription filter policies is delivered
    once and recorded as filtered out once, and the mirror publish reverses both."""
    sns = ctx.client("sns")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    topic_name = ctx.unique_name("sim2real-nd-filtmetric-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-check", "Value": check_tag}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    assert topic_arn.endswith(":" + topic_name), (
        f"the created topic ARN {topic_arn!r} does not end in the topic name {topic_name!r}, so the "
        f"TopicName metric dimension cannot be derived from it"
    )

    a_url, a_arn = _make_queue(ctx, f"sim2real-nd-filt-a-{suffix}", topic_arn, check_tag)
    b_url, b_arn = _make_queue(ctx, f"sim2real-nd-filt-b-{suffix}", topic_arn, check_tag)

    # Complementary policies: for any message carrying kind in {a, b}, exactly one subscription
    # matches. The exclusion is STRUCTURAL — no wait can make both match.
    sub_a = _subscribe(ctx, topic_arn, a_arn, {"kind": ["a"]}, check_tag)
    sub_b = _subscribe(ctx, topic_arn, b_arn, {"kind": ["b"]}, check_tag)
    subs = sorted(
        s["SubscriptionArn"] for s in sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    )
    assert subs == sorted([sub_a, sub_b]), (
        f"ListSubscriptionsByTopic reports {subs!r} on {topic_arn}, expected exactly "
        f"{sorted([sub_a, sub_b])!r} — a third subscriber would make the filtered-out count wrong"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)

    def _publish(kind, nonce):
        resp = sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"nonce": nonce}),
            MessageAttributes={"kind": {"DataType": "String", "StringValue": kind}},
        )
        assert resp.get("MessageId"), (
            f"Publish returned no MessageId for kind={kind!r}, so nothing below is attributable: "
            f"{resp!r}"
        )
        return resp["MessageId"]

    # ---- PHASE 1: kind=a. Queue A is the positive control and measures L; queue B is the negative.
    nonce_a = f"a-{uuid.uuid4().hex[:12]}"
    t0 = time.monotonic()
    _publish("a", nonce_a)
    got_a = _poll_until(
        lambda: _drain(ctx, a_url, seconds=4),
        lambda msgs: any(nonce_a in m["Message"] for m in msgs),
        timeout_s=120,
        interval_s=0,
        description=(
            f"the kind=a subscription delivered {nonce_a!r} to {a_url} — the positive leg of this "
            f"negative-delivery check and the measurement of L"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    assert len(got_a) == 1, (
        f"queue A holds {len(got_a)} message(s) for one publish, expected exactly 1: "
        f"{[m['Message'][:80] for m in got_a]!r}"
    )
    hold = max(3 * latency, 30.0)
    leaked_b = _drain(ctx, b_url, seconds=hold)
    assert leaked_b == [], (
        f"the kind=b subscription received {len(leaked_b)} message(s) during a {hold:.0f}s hold "
        f"(3x the {latency:.0f}s measured latency) for a publish carrying kind=a: "
        f"{[m['Message'][:80] for m in leaked_b]!r}"
    )
    assert _queue_depth(ctx, b_url) == 0, (
        f"queue B reports depth {_queue_depth(ctx, b_url)} behind an empty receive — the second "
        f"independent observable disagrees with the first"
    )

    # ---- PHASE 2: kind=b, the mirror. Both directions, so neither queue can be permanently dead.
    nonce_b = f"b-{uuid.uuid4().hex[:12]}"
    _publish("b", nonce_b)
    got_b = _poll_until(
        lambda: _drain(ctx, b_url, seconds=4),
        lambda msgs: any(nonce_b in m["Message"] for m in msgs),
        timeout_s=120,
        interval_s=0,
        description=(
            f"the kind=b subscription delivered {nonce_b!r} to {b_url} — proving queue B was withheld "
            f"in phase 1 by the filter policy and not by a broken endpoint"
        ),
    )
    assert len(got_b) == 1, (
        f"queue B holds {len(got_b)} message(s) for one publish, expected exactly 1: "
        f"{[m['Message'][:80] for m in got_b]!r}"
    )
    leaked_a = _drain(ctx, a_url, seconds=hold)
    assert leaked_a == [], (
        f"the kind=a subscription received {len(leaked_a)} message(s) during a {hold:.0f}s hold for a "
        f"publish carrying kind=b: {[m['Message'][:80] for m in leaked_a]!r}"
    )
    assert _queue_depth(ctx, a_url) == 0, (
        f"queue A reports depth {_queue_depth(ctx, a_url)} behind an empty receive"
    )

    # ---- THE POINT: SNS's own record that the withholding happened, on a fresh topic whose
    # lifetime counters are therefore exact. Two publishes, two deliveries, two filter rejections.
    published = _poll_until(
        lambda: _sns_metric(ctx, "NumberOfMessagesPublished", topic_name, since=window_start),
        lambda n: n >= 2,
        timeout_s=300,
        interval_s=15,
        description=(
            f"AWS/SNS NumberOfMessagesPublished for TopicName={topic_name} reached 2 — the anchor "
            f"that makes the two metrics below comparable"
        ),
    )
    assert published == 2, (
        f"NumberOfMessagesPublished Sum={published} for {topic_name}, expected exactly 2 — the topic "
        f"is freshly created and this check published twice"
    )
    delivered = _poll_until(
        lambda: _sns_metric(ctx, "NumberOfNotificationsDelivered", topic_name, since=window_start),
        lambda n: n >= 2,
        timeout_s=300,
        interval_s=15,
        description=(
            f"AWS/SNS NumberOfNotificationsDelivered for {topic_name} reached 2 — one accepted "
            f"delivery per publish"
        ),
    )
    assert delivered == 2, (
        f"NumberOfNotificationsDelivered Sum={delivered} for {topic_name}, expected exactly 2. Four "
        f"would mean the rejecting subscription's delivery was also counted, which the docs exclude: "
        f"'If the subscription rejects the message, the delivery attempt isn't counted for this metric'"
    )
    filtered = _poll_until(
        lambda: _sns_metric(ctx, "NumberOfNotificationsFilteredOut", topic_name, since=window_start),
        lambda n: n >= 1,
        timeout_s=300,
        interval_s=15,
        description=(
            f"AWS/SNS NumberOfNotificationsFilteredOut for {topic_name} recorded the withheld "
            f"notifications — the metric that separates 'correctly filtered out' from 'never sent'"
        ),
    )
    assert filtered == 2, (
        f"NumberOfNotificationsFilteredOut Sum={filtered} for {topic_name}, expected exactly 2 (one "
        f"non-matching subscription per publish, two publishes). 0 means the service kept no record "
        f"of the withholding and 'the queue was empty' is the only evidence left; a value "
        f"other than 2 means the metric is not counted per subscription"
    )
    by_attributes = _sns_metric(
        ctx, "NumberOfNotificationsFilteredOut-MessageAttributes", topic_name, since=window_start
    )
    assert 1 <= by_attributes <= filtered, (
        f"NumberOfNotificationsFilteredOut-MessageAttributes Sum={by_attributes} for {topic_name}, "
        f"expected between 1 and the aggregate {filtered} — both policies scope on message "
        f"attributes (the default), so the attribute-specific sub-metric must carry these rejections"
    )
    failed = _sns_metric(ctx, "NumberOfNotificationsFailed", topic_name, since=window_start)
    assert failed == 0, (
        f"NumberOfNotificationsFailed Sum={failed} for {topic_name}, expected 0 — a filtered-out "
        f"notification is not a delivery FAILURE, and conflating the two is exactly the confusion "
        f"this check exists to detect"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
