"""filtered-out-and-failed-notification-metrics-count-exactly-the-withheld-and-refused-publishes."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "filtered-out-and-failed-notification-metrics-count-exactly-the-withheld-and-refused-publishes"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sns"]

#: Publishes whose attributes NO subscription filter admits.
_N_FILTERED = 3
#: Publishes to a subscription whose endpoint policy denies SNS.
_N_FAILED = 2

#: A ceiling for the AWS/SNS series to reach the counts driven; never asserted as a latency.
_METRIC_BUDGET_S = 420.0
#: How long the denied endpoint is watched for a delivery once the counters reached their totals.
_ABSENCE_HOLD_S = 30.0
_DELIVERY_BUDGET_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """NumberOfNotificationsFilteredOut counts exactly the publishes a filter policy withheld and
    NumberOfNotificationsFailed exactly those a denying endpoint refused, neither absorbing the other,
    while a healthy subscription delivers: a silent drop and a correct filter must not look the same.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html
    """
    sns = ctx.client("sns")
    cw = ctx.client("cloudwatch")

    topic_arn = _create_topic(ctx, sns)
    topic_name = topic_arn.rsplit(":", 1)[-1]

    healthy_url, healthy_arn = _create_queue(ctx, "healthy-")
    denied_url, denied_arn = _create_queue(ctx, "denied-")

    # Subscription A: healthy endpoint, filter policy admits only attr=="admit".
    # This is the POSITIVE CONTROL and the filter that does the withholding.
    _allow_sns(ctx, healthy_url, healthy_arn, topic_arn)
    sub_a = _subscribe(ctx, sns, topic_arn, healthy_arn)
    sns.set_subscription_attributes(
        SubscriptionArn=sub_a,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps({"probe": ["admit"]}),
    )

    # Subscription B: NO filter policy (so every publish is offered to it) and an endpoint whose
    # policy explicitly DENIES sns.amazonaws.com, so the delivery attempt fails.
    _deny_sns(ctx, denied_url, denied_arn, topic_arn)
    _subscribe(ctx, sns, topic_arn, denied_arn)

    # ---- publish 1: the positive control. Admitted by A, refused by B's endpoint. ------------- #
    sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps({"leg": "control"}),
        MessageAttributes={"probe": {"DataType": "String", "StringValue": "admit"}},
    )
    bodies = _drain_until(
        ctx,
        healthy_url,
        want=1,
        timeout_s=_DELIVERY_BUDGET_S,
        description="the admitted publish arriving on the healthy subscription's queue",
    )
    assert len(bodies) == 1, (
        f"the healthy subscription received {len(bodies)} messages for the one admitted publish: "
        f"{bodies!r}. The pipeline must be demonstrably live before any absence or count below"
    )

    # ---- the two negatives, driven with attributes A's filter cannot admit -------------------- #
    for i in range(_N_FILTERED):
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"leg": "filtered", "i": i}),
            MessageAttributes={"probe": {"DataType": "String", "StringValue": "withhold"}},
        )
    # Every one of those _N_FILTERED publishes is ALSO offered to subscription B (no filter policy)
    # and fails there, so B's failures so far are 1 (control) + _N_FILTERED. To keep the two counts
    # independently attributable, the expected Failed total is stated as that arithmetic rather than
    # as a bare literal.
    expected_failed = float(1 + _N_FILTERED)
    for i in range(_N_FAILED):
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"leg": "failed-only", "i": i}),
            MessageAttributes={"probe": {"DataType": "String", "StringValue": "withhold"}},
        )
    expected_filtered = float(_N_FILTERED + _N_FAILED)
    expected_failed += float(_N_FAILED)
    expected_published = float(1 + _N_FILTERED + _N_FAILED)

    # ---- terminal read at CloudWatch ---------------------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=30)

    def _dps(metric: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/SNS",
            MetricName=metric,
            Dimensions=[{"Name": "TopicName", "Value": topic_name}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=10),
            Period=300,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    def _sum(metric: str) -> float | None:
        dps = _dps(metric)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Polled until every counter reaches the publishes driven; an over-count still fails below.
    expected = (expected_published, expected_filtered, expected_failed)
    published_n, filtered, failed = _poll_until(
        lambda: _triple(
            _sum("NumberOfMessagesPublished"),
            _sum("NumberOfNotificationsFilteredOut"),
            _sum("NumberOfNotificationsFailed"),
        ),
        lambda t: t is not None and all(got >= want for got, want in zip(t, expected)),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=10.0,
        description=(
            f"AWS/SNS NumberOfMessagesPublished / NumberOfNotificationsFilteredOut / "
            f"NumberOfNotificationsFailed for TopicName={topic_name} reaching {expected!r}"
        ),
    )

    assert published_n == expected_published, (
        f"AWS/SNS NumberOfMessagesPublished Sum for TopicName={topic_name} settled at "
        f"{published_n!r}, expected {expected_published} — this check issued exactly that many "
        f"Publish calls, so the two counters below are being read against a known denominator"
    )
    assert filtered == expected_filtered, (
        f"AWS/SNS NumberOfNotificationsFilteredOut Sum for TopicName={topic_name} settled at "
        f"{filtered!r}, expected {expected_filtered} — the {_N_FILTERED + _N_FAILED} publishes "
        f"carrying probe='withhold' against a subscription filter that admits only 'admit'. This is "
        f"the counter that distinguishes 'correctly filtered' from 'silently dropped'"
    )
    assert failed == expected_failed, (
        f"AWS/SNS NumberOfNotificationsFailed Sum for TopicName={topic_name} settled at {failed!r}, "
        f"expected {expected_failed} — every publish is offered to the unfiltered subscription "
        f"whose endpoint policy denies sns.amazonaws.com, so all "
        f"{int(expected_published)} attempts there must fail"
    )
    for metric in (
        "NumberOfMessagesPublished",
        "NumberOfNotificationsFilteredOut",
        "NumberOfNotificationsFailed",
    ):
        dps = _dps(metric)
        assert dps, f"AWS/SNS {metric} vanished on re-read for TopicName={topic_name}: {dps!r}"
        units = {d.get("Unit") for d in dps}
        assert units == {"Count"}, (
            f"AWS/SNS {metric} datapoints for TopicName={topic_name} carry Unit(s) {units!r}, "
            f"expected exactly {{'Count'}}"
        )

    sets = _dimension_sets(cw, "AWS/SNS", "TopicName", topic_name)
    assert ("TopicName",) in sets, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/SNS series naming "
        f"TopicName={topic_name}; the per-topic ('TopicName',) series must exist, because that is "
        f"the only series a per-topic dashboard or alarm can be built on"
    )

    # ---- the absence that closes it: nothing was DELIVERED to the denied endpoint ------------- #
    # Held only now, after the counters settled, so the pipeline is demonstrably live.
    _assert_stays(
        lambda: _received_count(ctx, denied_url),
        0,
        hold_s=_ABSENCE_HOLD_S,
        interval_s=10.0,
        description=(
            f"the subscription whose queue policy denies sns.amazonaws.com received nothing, so "
            f"the {int(expected_failed)} failures counted above are real failures and not "
            f"deliveries the metric mislabelled"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum("NumberOfNotificationsFilteredOut")
    assert final == expected_filtered, (
        f"after the absence window NumberOfNotificationsFilteredOut read {final!r}, expected "
        f"{expected_filtered}"
    )


# ===== helpers =====
def _create_topic(ctx, sns) -> str:
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-cwsns-topic-"),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__sns"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, label: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-cwsns-{label}"),
        tags={"sim2real": "cloudwatch__sns"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _allow_sns(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowSNS",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )


def _deny_sns(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    """An EXPLICIT Deny, so the refusal is unambiguous rather than an omitted Allow."""
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenySNS",
                            "Effect": "Deny",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )


def _subscribe(ctx, sns, topic_arn: str, queue_arn: str) -> str:
    arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=arn))
    return arn


def _received_count(ctx, queue_url: str) -> int:
    """How many messages this call could pull off the queue. Anything found is deleted, so a later
    poll cannot re-count the same arrival."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return len(msgs)


def _drain_until(ctx, queue_url: str, *, want: int, timeout_s: float, description: str) -> list[str]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    bodies: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if len(bodies) >= want:
            return bodies
    raise AssertionError(
        f"{description}: only {len(bodies)} of {want} messages arrived within {timeout_s}s; "
        f"bodies were {bodies!r}"
    )


def _triple(a, b, c):
    return None if a is None or b is None or c is None else (a, b, c)


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="reading"):
    """Poll probe() until predicate holds; fail quoting the last reading at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last reading {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=30.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
