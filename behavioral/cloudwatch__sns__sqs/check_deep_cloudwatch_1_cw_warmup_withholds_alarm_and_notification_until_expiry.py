"""deep-cloudwatch-1-cw-warmup-withholds-alarm-and-notification-until-expiry."""
from __future__ import annotations

# One custom-namespace series is breaching before any alarm exists. A no-warm-up control alarm
# (Period=60, Maximum, 1/1) reaches ALARM after a delivery latency L. A one-minute warm-up is
# shorter than L, so it cannot be held against the control for 3L at all. The warm-up here is
# therefore _WARMUP_MIN minutes, sized so that a 3L hold (measured from the instant all arms were
# created) fits inside it with margin, while the whole check still fits a 600s single-command
# budget. The series is also backdated one period before any alarm exists, so every arm has a
# complete period to evaluate from its first evaluation and L is as short as possible.
# During warm-up DescribeAlarms reports EvaluationState == "IN_WARM_UP" and StateReason "Alarm is
# in Warm-Up". "IN_WARM_UP" is NOT a member of the Smithy EvaluationState enum (PARTIAL_DATA |
# EVALUATION_FAILURE | EVALUATION_ERROR). After the warm-up expires the field is ABSENT, and it is
# absent on the control throughout.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deep-cloudwatch-1-cw-warmup-withholds-alarm-and-notification-until-expiry"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_WARMUP_MIN = 7
_WARMUP_S = _WARMUP_MIN * 60
_THRESHOLD = 10.0
_BREACH = 100.0
_IN_WARM_UP = "IN_WARM_UP"


# timing:real-time — cooldown: 420 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With OnlyStartEvaluatingAfterWarmUpPeriodEnds true, a breaching alarm stays INSUFFICIENT_DATA
    in warm-up with no action or notification while its twins (no warm-up, flag false) deliver, then
    enters ALARM and notifies no earlier than the warm-up after its configuration."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    namespace = ctx.unique_name("Sim2RealWarmUpNs")
    metric = "WarmUpSignal"
    control_name = ctx.unique_name("sim2real-warmup-control-")
    gated_name = ctx.unique_name("sim2real-warmup-gated-")
    early_name = ctx.unique_name("sim2real-warmup-early-")
    tags_kv = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:check", "Value": CHECK},
    ]

    # --- the delivery path: SNS topic -> SQS queue -------------------------------------------- #
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-warmup-topic-"), Tags=tags_kv)[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-warmup-queue-"),
        tags={t["Key"]: t["Value"] for t in tags_kv},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
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
    subscription_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=subscription_arn))

    def _tick() -> None:
        """Keep the shared series breaching in the current minute (Maximum, so idempotent)."""
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": datetime.now(timezone.utc),
                    "Value": _BREACH,
                    "Unit": "Count",
                }
            ],
        )

    # The series is breaching BEFORE any alarm exists -- including one full period back -- so data
    # is available to every arm from its first evaluation, which is exactly the case
    # OnlyStartEvaluatingAfterWarmUpPeriodEnds gates.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": datetime.now(timezone.utc) - timedelta(seconds=60),
                "Value": _BREACH,
                "Unit": "Count",
            }
        ],
    )
    _tick()

    common = dict(
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        Tags=tags_kv,
    )
    created_at = time.monotonic()
    cw.put_metric_alarm(AlarmName=control_name, AlarmDescription="sim2real: no warm-up", **common)
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[control_name]))
    cw.put_metric_alarm(
        AlarmName=gated_name,
        AlarmDescription="sim2real: warm-up, wait the full period",
        WarmUpConfiguration={
            "WarmUpPeriodDurationInMinutes": _WARMUP_MIN,
            "OnlyStartEvaluatingAfterWarmUpPeriodEnds": True,
        },
        **common,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[gated_name]))
    cw.put_metric_alarm(
        AlarmName=early_name,
        AlarmDescription="sim2real: warm-up, may end early on data",
        WarmUpConfiguration={
            "WarmUpPeriodDurationInMinutes": _WARMUP_MIN,
            "OnlyStartEvaluatingAfterWarmUpPeriodEnds": False,
        },
        **common,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[early_name]))

    # --- configuration read-back, and the warm-up state at birth ------------------------------ #
    control0 = _alarm(cw, control_name)
    gated0 = _alarm(cw, gated_name)
    early0 = _alarm(cw, early_name)
    assert "WarmUpConfiguration" not in control0, (
        f"the control reports WarmUpConfiguration {control0.get('WarmUpConfiguration')!r}; it must "
        f"have none, or it is not a control for warm-up"
    )
    assert gated0.get("WarmUpConfiguration") == {
        "WarmUpPeriodDurationInMinutes": _WARMUP_MIN,
        "OnlyStartEvaluatingAfterWarmUpPeriodEnds": True,
    }, f"the gated arm read back WarmUpConfiguration {gated0.get('WarmUpConfiguration')!r}"
    assert early0.get("WarmUpConfiguration") == {
        "WarmUpPeriodDurationInMinutes": _WARMUP_MIN,
        "OnlyStartEvaluatingAfterWarmUpPeriodEnds": False,
    }, f"the early arm read back WarmUpConfiguration {early0.get('WarmUpConfiguration')!r}"
    assert gated0["StateValue"] == "INSUFFICIENT_DATA", (
        f"the gated arm was born in {gated0['StateValue']!r}, expected INSUFFICIENT_DATA"
    )
    assert gated0.get("EvaluationState") == _IN_WARM_UP, (
        f"the gated arm reports EvaluationState {gated0.get('EvaluationState')!r} at creation; real "
        f"AWS reports {_IN_WARM_UP!r} for an alarm inside its warm-up (a value the Smithy enum does "
        f"not declare)"
    )
    assert "EvaluationState" not in control0, (
        f"the control reports EvaluationState {control0.get('EvaluationState')!r}; an alarm with "
        f"no warm-up and no evaluation problem carries none"
    )
    config_ts = gated0["AlarmConfigurationUpdatedTimestamp"]

    _drain(sqs, queue_url)

    # --- the barrier: the control delivers, and its latency calibrates the hold ---------------- #
    by_alarm: dict = {}
    _poll_until(
        lambda: _collect(sqs, queue_url, into=by_alarm),
        lambda seen: control_name in seen,
        timeout_s=300.0,
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"the no-warm-up control {control_name!r} delivered its ALARM notification through "
            f"SNS -> SQS on a series that has been breaching since before it existed"
        ),
    )
    latency_s = time.monotonic() - created_at
    assert gated_name not in by_alarm, (
        f"the gated arm delivered {by_alarm[gated_name]!r} in the same window as the control, "
        f"while inside a {_WARMUP_MIN}-minute warm-up"
    )
    # The hold is 3L, capped 30s short of the warm-up itself: past that point the warm-up, not the
    # control's latency, is the time semantic, and the expiry leg grades it server-side.
    assert latency_s + 30.0 < _WARMUP_S, (
        f"the control needed {latency_s:.0f}s to deliver, past the {_WARMUP_S}s warm-up less 30s; "
        f"the absence cannot be calibrated against a control this slow"
    )
    hold_until = created_at + min(3.0 * latency_s, _WARMUP_S - 30.0)
    control_after = _alarm(cw, control_name)
    assert control_after["StateValue"] == "ALARM", (
        f"the control delivered but reports StateValue {control_after['StateValue']!r}"
    )
    assert "EvaluationState" not in control_after, (
        f"the control in ALARM reports EvaluationState {control_after.get('EvaluationState')!r}"
    )

    # --- the one-field twin: OnlyStartEvaluatingAfterWarmUpPeriodEnds=false ends warm-up early - #
    _poll_until(
        lambda: _collect(sqs, queue_url, into=by_alarm),
        lambda seen: early_name in seen,
        timeout_s=max(hold_until - time.monotonic(), 60.0),
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"the early arm {early_name!r} (OnlyStartEvaluatingAfterWarmUpPeriodEnds=false) ended "
            f"its warm-up on available data and delivered, well before its {_WARMUP_S}s warm-up "
            f"would have expired"
        ),
    )
    early_ok = _alarm(cw, early_name)
    assert early_ok["StateValue"] == "ALARM", (
        f"the early arm delivered but reports StateValue {early_ok['StateValue']!r}"
    )
    assert "EvaluationState" not in early_ok, (
        f"the early arm left warm-up but still reports EvaluationState "
        f"{early_ok.get('EvaluationState')!r}"
    )

    # --- the hold: withheld transition and nothing delivered until >= 3L since creation -------- #
    while True:
        _tick()
        _collect(sqs, queue_url, into=by_alarm)
        assert gated_name not in by_alarm, (
            f"the gated arm delivered {by_alarm[gated_name]!r} "
            f"{time.monotonic() - created_at:.0f}s after creation, inside its {_WARMUP_S}s warm-up "
            f"with OnlyStartEvaluatingAfterWarmUpPeriodEnds=true (control latency {latency_s:.0f}s)"
        )
        held = _alarm(cw, gated_name)
        assert held["StateValue"] == "INSUFFICIENT_DATA", (
            f"the gated arm reports {held['StateValue']!r} "
            f"{time.monotonic() - created_at:.0f}s into a {_WARMUP_S}s warm-up; its transition must "
            f"be withheld even though the series is breaching (reason {held.get('StateReason')!r})"
        )
        assert held.get("EvaluationState") == _IN_WARM_UP, (
            f"the gated arm reports EvaluationState {held.get('EvaluationState')!r} during the "
            f"hold, expected {_IN_WARM_UP!r}"
        )
        fired = _action_history(cw, gated_name)
        assert not fired, (
            f"the gated arm has Action history {fired!r} inside its warm-up; no action may run"
        )
        assert _action_history(cw, control_name), (
            f"the control {control_name!r} has an EMPTY Action history although its notification "
            f"was delivered; the hold is only meaningful against a control that demonstrably acts"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(10.0)

    # --- expiry: the withheld transition and notification are DEMANDED ------------------------ #
    remaining = _WARMUP_S - (time.monotonic() - created_at)
    _poll_until(
        lambda: _collect(sqs, queue_url, into=by_alarm),
        lambda seen: gated_name in seen,
        timeout_s=max(remaining, 0.0) + 300.0,
        interval_s=10.0,
        on_iteration=_tick,
        description=(
            f"the gated arm {gated_name!r} delivered its withheld ALARM notification once its "
            f"{_WARMUP_S}s warm-up expired; a warm-up that never ends is a page that never arrives"
        ),
    )
    payload = by_alarm[gated_name][0]
    assert payload["NewStateValue"] == "ALARM", (
        f"the released notification reports NewStateValue {payload['NewStateValue']!r}"
    )
    assert payload["OldStateValue"] == "INSUFFICIENT_DATA", (
        f"the released notification reports OldStateValue {payload['OldStateValue']!r}; the arm "
        f"must have been held at INSUFFICIENT_DATA for the whole warm-up"
    )
    released = _alarm(cw, gated_name)
    assert released["StateValue"] == "ALARM", (
        f"the gated arm delivered but reports StateValue {released['StateValue']!r}"
    )
    gated_for_s = (released["StateUpdatedTimestamp"] - config_ts).total_seconds()
    assert gated_for_s >= _WARMUP_S, (
        f"the gated arm transitioned {gated_for_s:.1f}s after its configuration timestamp "
        f"{config_ts.isoformat()}, sooner than its {_WARMUP_S}s warm-up"
    )
    assert "EvaluationState" not in released, (
        f"the gated arm left warm-up but still reports EvaluationState "
        f"{released.get('EvaluationState')!r}; it must be absent once evaluation is healthy"
    )
    invoked = _poll_until(
        lambda: _action_history(cw, gated_name),
        lambda items: any(_action_state(i) == "Succeeded" for i in items),
        timeout_s=120.0,
        interval_s=5.0,
        on_iteration=_tick,
        description=f"a Succeeded Action history item recorded for {gated_name!r} after expiry",
    )
    succeeded = [i for i in invoked if _action_state(i) == "Succeeded"]
    assert any(topic_arn in i["HistorySummary"] for i in succeeded), (
        f"the gated arm's Succeeded Action history {[i['HistorySummary'] for i in succeeded]!r} "
        f"does not name the topic {topic_arn!r}"
    )


def _alarm(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == name:
                return alarm
    raise AssertionError(f"metric alarm {name!r} is not present in DescribeAlarms")


def _action_history(cw, name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name,
        HistoryItemType="Action",
        AlarmTypes=["MetricAlarm"],
        ScanBy="TimestampDescending",
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _action_state(item):
    data = json.loads(item["HistoryData"])
    state = data.get("actionState")
    assert state, f"an Action history item has no actionState in its HistoryData: {item!r}"
    return state


def _drain(sqs, queue_url) -> None:
    while True:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not received:
            return
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[{"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(received)],
        )


def _collect(sqs, queue_url, *, into):
    """Receive and DELETE every SNS envelope, folding {AlarmName: [payload, ...]} into *into*."""
    while True:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        if not received:
            return into
        for message in received:
            envelope = json.loads(message["Body"])
            assert envelope.get("Type") == "Notification", (
                f"expected an SNS Notification envelope on the queue, got {envelope!r}"
            )
            payload = json.loads(envelope["Message"])
            name = payload.get("AlarmName")
            assert name, f"an alarm notification arrived with no AlarmName: {payload!r}"
            into.setdefault(name, []).append(payload)
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[{"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(received)],
        )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s:.0f}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
