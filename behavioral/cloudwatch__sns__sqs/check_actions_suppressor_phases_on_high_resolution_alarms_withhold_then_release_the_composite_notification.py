"""actions-suppressor-phases-on-high-resolution-alarms-withhold-then-release-the-composite-notification."""
from __future__ import annotations

# Both alarms move by published datapoints and real evaluation, never by SetAlarmState: a
# temporary forced state can report an action hand-off as Succeeded while its consumer does
# nothing, which is indistinguishable from the withheld-or-delivered outcome asserted here.

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "actions-suppressor-phases-on-high-resolution-alarms-withhold-then-release-the-composite-notification"
GROUP = "alerting"
SERVICES = ["cloudwatch", "sns", "sqs"]

_WAIT_PERIOD_S = 120
_EXTENSION_PERIOD_S = 60
#: Both metric alarms evaluate a high-resolution series over 10 s periods, 1 breaching of 3.
_PERIOD_S = 10
_EVALUATION_PERIODS = 3
_SUPPRESSOR_THRESHOLD = 10.0
_SUPPRESSOR_BREACH = 100.0
_SUPPRESSOR_CLEAR = 1.0
#: The child is driven by real datapoints too (see the header note on SetAlarmState), so it needs a
#: threshold and a breaching value of its own.
_CHILD_THRESHOLD = 10.0
_CHILD_BREACH = 100.0


# timing:real-time — metric: 60 s
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A suppressed composite alarm reports ActionsSuppressedBy WaitPeriod, Alarm, then
    ExtensionPeriod, recording only Suppressed actions and delivering nothing as its unsuppressed
    twin delivers, then notifies once the extension ends.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-suppression.html
    """
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    namespace = ctx.unique_name("Sim2RealSuppressorNs")
    suppressor_metric = "SuppressorSignal"
    child_name = ctx.unique_name("sim2real-suppressor-child-")
    suppressor_name = ctx.unique_name("sim2real-suppressor-gate-")
    suppressed_name = ctx.unique_name("sim2real-suppressor-composite-")
    control_name = ctx.unique_name("sim2real-suppressor-control-")

    tags_kv = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:check", "Value": CHECK},
    ]

    # --- the delivery path: SNS topic -> SQS queue -------------------------------------------- #
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-suppressor-topic-"),
        Tags=tags_kv,
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-suppressor-queue-"),
        tags={t["Key"]: t["Value"] for t in tags_kv},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
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
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=subscription_arn)
    )

    # --- both alarms are moved by REAL datapoints, never by SetAlarmState --------------------- #
    # Maximum over a 10 s period, so republishing the same value inside one period is idempotent and
    # a poll body can keep the newest period populated without the series drifting.
    child_metric = "ChildSignal"
    suppressor_value = [_SUPPRESSOR_CLEAR]
    child_value = [0.0]

    def _publish(metric: str, value: float) -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": datetime.now(timezone.utc),
                    "Value": value,
                    "StorageResolution": 1,
                    "Unit": "Count",
                }
            ],
        )

    def _tick() -> None:
        """Keep BOTH series populated in the current period, at their current commanded values."""
        _publish(suppressor_metric, suppressor_value[0])
        _publish(child_metric, child_value[0])

    _tick()
    cw.put_metric_alarm(
        AlarmName=suppressor_name,
        Namespace=namespace,
        MetricName=suppressor_metric,
        Statistic="Maximum",
        Period=_PERIOD_S,
        EvaluationPeriods=_EVALUATION_PERIODS,
        DatapointsToAlarm=1,
        Threshold=_SUPPRESSOR_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=False,
        AlarmDescription="sim2real depth: the suppressor gate for a composite alarm",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[suppressor_name]))

    # --- the child: a real metric alarm, moved by real datapoints ------------------------------ #
    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName=child_metric,
        Statistic="Maximum",
        Period=_PERIOD_S,
        EvaluationPeriods=_EVALUATION_PERIODS,
        DatapointsToAlarm=1,
        Threshold=_CHILD_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        # notBreaching, not breaching: the child must sit in OK until this check decides to move it,
        # so that the composites are created over a quiet child and beat 1 is a real transition.
        TreatMissingData="notBreaching",
        ActionsEnabled=False,
        AlarmDescription="sim2real depth: the child whose ALARM drives both composites",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[child_name]))

    # Both alarms must be in OK BEFORE either composite exists: the suppressor because beat 1 is
    # only the WaitPeriod case if the suppressor is NOT in ALARM, and the child because beat 1 must
    # be a genuine OK -> ALARM transition rather than a state the composite inherited at birth.
    _poll_until(
        lambda: (_metric_alarm(cw, suppressor_name), _metric_alarm(cw, child_name)),
        lambda pair: all(a["StateValue"] == "OK" for a in pair),
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the suppressor {suppressor_name!r} and the child {child_name!r} both evaluated their "
            f"below-threshold datapoints and reached OK, which is the precondition that makes "
            f"beat 1 both a real transition and the WaitPeriod case"
        ),
        on_iteration=_tick,
    )

    # --- the two composites: identical but for the suppressor --------------------------------- #
    rule = f'ALARM("{child_name}")'
    cw.put_composite_alarm(
        AlarmName=suppressed_name,
        AlarmRule=rule,
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        ActionsSuppressor=suppressor_name,
        ActionsSuppressorWaitPeriod=_WAIT_PERIOD_S,
        ActionsSuppressorExtensionPeriod=_EXTENSION_PERIOD_S,
        AlarmDescription="sim2real depth: the SUPPRESSED composite",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[suppressed_name]))
    cw.put_composite_alarm(
        AlarmName=control_name,
        AlarmRule=rule,
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
        AlarmDescription="sim2real depth: the UNSUPPRESSED twin control",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[control_name]))

    configured = _composite_alarm(cw, suppressed_name)
    assert configured["ActionsSuppressor"].endswith(suppressor_name), (
        f"the suppressed composite reports ActionsSuppressor "
        f"{configured.get('ActionsSuppressor')!r}, expected an identifier ending in "
        f"{suppressor_name!r}"
    )
    assert configured["ActionsSuppressorWaitPeriod"] == _WAIT_PERIOD_S, (
        f"ActionsSuppressorWaitPeriod read back "
        f"{configured.get('ActionsSuppressorWaitPeriod')!r}, expected {_WAIT_PERIOD_S!r}"
    )
    assert configured["ActionsSuppressorExtensionPeriod"] == _EXTENSION_PERIOD_S, (
        f"ActionsSuppressorExtensionPeriod read back "
        f"{configured.get('ActionsSuppressorExtensionPeriod')!r}, expected "
        f"{_EXTENSION_PERIOD_S!r}"
    )
    control_configured = _composite_alarm(cw, control_name)
    assert "ActionsSuppressor" not in control_configured, (
        f"the twin control reports ActionsSuppressor "
        f"{control_configured.get('ActionsSuppressor')!r}; it must have none, or it is not a "
        f"control for suppression at all"
    )
    assert control_configured["AlarmRule"] == configured["AlarmRule"], (
        f"the two composites' rules differ: {control_configured['AlarmRule']!r} vs "
        f"{configured['AlarmRule']!r}. They must watch the same child, or their notifications are "
        f"not comparable"
    )

    _drain(sqs, queue_url)  # start from an empty queue; nothing has fired yet

    # --- beat 1: the composite enters ALARM while the suppressor is OK ------------------------- #
    delivery_start = time.monotonic()
    # A real breaching datapoint, not SetAlarmState: a forced state is temporary and does not
    # reliably drive a consumer of an alarm action (see the header note).
    child_value[0] = _CHILD_BREACH
    _tick()
    _poll_until(
        lambda: _metric_alarm(cw, child_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the child {child_name!r} transitioned OK -> ALARM by real evaluation of a breaching "
            f"datapoint, which is what both composites' AlarmRule watches"
        ),
        on_iteration=_tick,
    )
    waiting = _poll_until(
        lambda: _composite_alarm(cw, suppressed_name),
        lambda a: a["StateValue"] == "ALARM" and a.get("ActionsSuppressedBy") == "WaitPeriod",
        timeout_s=float(_WAIT_PERIOD_S) - 30.0,
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"the suppressed composite {suppressed_name!r} entered ALARM reporting "
            f"ActionsSuppressedBy == 'WaitPeriod'. Its suppressor is in OK, so CloudWatch is "
            f"waiting up to {_WAIT_PERIOD_S}s for the suppressor to confirm a maintenance window; "
            f"a target that renders only 'Alarm', or nothing, fails here"
        ),
    )
    assert waiting.get("ActionsSuppressedReason"), (
        f"the composite is suppressed by WaitPeriod but reports ActionsSuppressedReason "
        f"{waiting.get('ActionsSuppressedReason')!r}; the reason is the only field that tells an "
        f"operator why their page did not arrive"
    )
    # A suppressed composite records an Action history entry immediately, with HistorySummary
    # "Successfully suppressed (by WaitPeriod) action <topic-arn>" and actionState "Suppressed":
    # every item recorded during suppression is marked Suppressed, never Succeeded.
    suppressed_actions = _action_history(cw, suppressed_name)
    assert suppressed_actions, (
        f"the suppressed composite {suppressed_name!r} has no Action history at all while it "
        f"reports itself suppressed by WaitPeriod; real AWS records a 'Suppressed' entry the "
        f"instant the composite withholds, so an empty history here means the action was never "
        f"even attempted"
    )
    assert all(_action_state(item) == "Suppressed" for item in suppressed_actions), (
        f"the suppressed composite's Action history {suppressed_actions!r} contains an entry not "
        f"marked actionState=='Suppressed' while ActionsSuppressedBy == 'WaitPeriod' -- suppression "
        f"must withhold the actual invocation, not just record itself afterward"
    )

    # --- beat 2: the suppressor takes over, and the twin proves the path is live --------------- #
    suppressor_value[0] = _SUPPRESSOR_BREACH
    _tick()
    _poll_until(
        lambda: _metric_alarm(cw, suppressor_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the suppressor {suppressor_name!r} transitioned to ALARM by real evaluation, opening "
            f"the maintenance window. Not SetAlarmState: a forced suppressor state may not be "
            f"honoured by the suppression machinery at all, which would make the absence asserted "
            f"below pass against a CORRECT target"
        ),
        on_iteration=_tick,
    )
    # One shared accumulator, so every poll pass folds what it drained into the same dict -- a
    # fresh dict per pass would silently discard the notification that arrived two passes ago.
    by_alarm: dict = {}
    _poll_until(
        lambda: _collect(sqs, queue_url, into=by_alarm),
        lambda seen: control_name in seen,
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the UNSUPPRESSED twin {control_name!r} delivered its notification through "
            f"SNS -> SQS. This is the demonstrated control: without it, the suppressed composite's "
            f"silence would also be scored green against a target that can deliver nothing at all"
        ),
        on_iteration=_tick,
    )
    latency_s = time.monotonic() - delivery_start
    assert suppressed_name not in by_alarm, (
        f"the SUPPRESSED composite delivered {len(by_alarm.get(suppressed_name, []))} "
        f"notification(s) in the same window in which its unsuppressed twin delivered "
        f"{len(by_alarm[control_name])}. Its ActionsSuppressor was in ALARM, so its actions must "
        f"be withheld"
    )
    suppressed_now = _poll_until(
        lambda: _composite_alarm(cw, suppressed_name),
        lambda a: a.get("ActionsSuppressedBy") == "Alarm",
        timeout_s=90.0,
        interval_s=5.0,
        description=(
            f"the suppressed composite {suppressed_name!r} moved from the WaitPeriod phase to "
            f"ActionsSuppressedBy == 'Alarm' once its suppressor actually reached ALARM"
        ),
        on_iteration=_tick,
    )
    assert suppressed_now["StateValue"] == "ALARM", (
        f"the suppressed composite reports StateValue {suppressed_now['StateValue']!r}; "
        f"suppression withholds ACTIONS and must not change the composite's own state, or the "
        f"remaining beats are about a different alarm"
    )

    # The control's SQS delivery (just proven above) only shows SNS already published; confirm
    # CloudWatch's own DescribeAlarmHistory Action item is ALSO present before starting the
    # absence-hold clock, or the very first read inside the hold could catch a real lag and fail a
    # target that is behaving correctly. With the right AlarmTypes (see `_action_history`) the item
    # is present at the first read; this poll's timeout is a safety margin.
    _poll_until(
        lambda: _action_history(cw, control_name),
        lambda items: bool(items),
        timeout_s=60.0,
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"the UNSUPPRESSED twin {control_name!r} recorded an Action history item server-side, "
            f"confirming CloudWatch's own record catches up with the SNS delivery already observed "
            f"on the queue"
        ),
    )

    # Absence bounded by the control's latency on the same wiring. `_tick` keeps publishing: the
    # child alarm has TreatMissingData="notBreaching", so a gap longer than its evaluation range reverts
    # it (and the composite watching it) to OK, which would break beat 3's ALARM assertion.
    hold_s = max(2.0 * latency_s, 60.0)
    _assert_stays_silent(
        sqs,
        queue_url,
        cw,
        suppressed_name,
        control_name,
        hold_s=hold_s,
        latency_s=latency_s,
        tick=_tick,
    )

    # --- beat 3: the suppressor clears, and the EXTENSION phase keeps withholding -------------- #
    suppressor_value[0] = _SUPPRESSOR_CLEAR
    _tick()
    _poll_until(
        lambda: _metric_alarm(cw, suppressor_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the suppressor {suppressor_name!r} transitioned back to OK by real evaluation of a "
            f"below-threshold datapoint, closing the maintenance window and starting the "
            f"{_EXTENSION_PERIOD_S}s extension"
        ),
        on_iteration=_tick,
    )
    extending = _poll_until(
        lambda: _composite_alarm(cw, suppressed_name),
        lambda a: a.get("ActionsSuppressedBy") == "ExtensionPeriod",
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the suppressed composite entered the ExtensionPeriod phase after its suppressor left "
            f"ALARM; CloudWatch keeps withholding for {_EXTENSION_PERIOD_S}s so a recovering "
            f"system is not paged mid-recovery. A boolean 'suppressed / not suppressed' "
            f"implementation skips this phase entirely and either fires immediately or never"
        ),
        on_iteration=_tick,
    )
    assert extending["StateValue"] == "ALARM", (
        f"the composite reports StateValue {extending['StateValue']!r} in the ExtensionPeriod "
        f"phase, expected ALARM -- the extension is about withholding an action, not about "
        f"changing state"
    )
    assert extending.get("ActionsSuppressedReason"), (
        f"the composite is suppressed by ExtensionPeriod but reports ActionsSuppressedReason "
        f"{extending.get('ActionsSuppressedReason')!r}"
    )
    assert suppressed_name not in _collect(sqs, queue_url, into=by_alarm), (
        f"the suppressed composite delivered a notification while reporting itself suppressed by "
        f"ExtensionPeriod: {by_alarm.get(suppressed_name)!r}"
    )

    # --- beat 4: the extension elapses and the notification arrives AT THE CONSUMER ------------ #
    released = _poll_until(
        lambda: _collect(sqs, queue_url, into=by_alarm),
        lambda seen: suppressed_name in seen,
        timeout_s=float(_EXTENSION_PERIOD_S) + 120.0,
        interval_s=10.0,
        on_iteration=_tick,
        description=(
            f"the suppressed composite {suppressed_name!r} delivered its withheld notification "
            f"once the {_EXTENSION_PERIOD_S}s extension elapsed. Suppression that never ends is a "
            f"page that never arrives, which is the failure this beat exists to catch"
        ),
    )
    payload = released[suppressed_name][0]
    assert payload["AlarmName"] == suppressed_name, (
        f"the released notification names alarm {payload['AlarmName']!r}, expected "
        f"{suppressed_name!r} -- the twin control publishes to the same topic, so the AlarmName is "
        f"what attributes this delivery to the suppressed composite"
    )
    assert payload["NewStateValue"] == "ALARM", (
        f"the released notification reports NewStateValue {payload['NewStateValue']!r}, expected "
        f"ALARM: the composite has been in ALARM throughout, and the extension elapsing is what "
        f"released the action"
    )
    final = _composite_alarm(cw, suppressed_name)
    assert final.get("ActionsSuppressedBy") in (None, ""), (
        f"after the notification was delivered the composite still reports ActionsSuppressedBy "
        f"{final.get('ActionsSuppressedBy')!r}; nothing is suppressing it any more"
    )
    # By this point the composite already has earlier 'Suppressed' Action-history entries (beat 1),
    # so "any item exists" is met trivially -- the real predicate is a Succeeded item, the
    # actionState CloudWatch records for a genuine invocation.
    invoked = _poll_until(
        lambda: _action_history(cw, suppressed_name),
        lambda items: any(_action_state(item) == "Succeeded" for item in items),
        timeout_s=120.0,
        interval_s=5.0,
        on_iteration=_tick,
        description=(
            f"a Succeeded Action history item recorded server-side for {suppressed_name!r}; the SQS "
            f"message proves delivery at the consumer and this proves CloudWatch itself recorded "
            f"the invocation, not just another suppression"
        ),
    )
    fired = [item for item in invoked if _action_state(item) == "Succeeded"]
    assert any(topic_arn in item["HistorySummary"] for item in fired), (
        f"the composite's Succeeded Action history {[i['HistorySummary'] for i in fired]!r} does "
        f"not name the topic {topic_arn!r} that was actually invoked"
    )


def _metric_alarm(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == name:
                return alarm
    raise AssertionError(f"metric alarm {name!r} is not present in DescribeAlarms")


def _composite_alarm(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["CompositeAlarm"]
    ):
        for alarm in page.get("CompositeAlarms", []):
            if alarm["AlarmName"] == name:
                return alarm
    raise AssertionError(f"composite alarm {name!r} is not present in DescribeAlarms")


def _action_history(cw, name):
    """A composite alarm's Action history items.

    DescribeAlarmHistory without AlarmTypes covers metric alarms only and returns no items for a
    composite alarm, so AlarmTypes=['CompositeAlarm'] is pinned.
    """
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name,
        HistoryItemType="Action",
        AlarmTypes=["CompositeAlarm"],
        ScanBy="TimestampDescending",
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _action_state(item):
    """The real signal inside an Action history item: HistoryData is a JSON string carrying
    actionState in {"Suppressed", "Succeeded", ...}; a suppressed item's HistorySummary also names
    the topic ARN, so only this field distinguishes withheld from invoked.
    """
    data = json.loads(item["HistoryData"])
    state = data.get("actionState")
    assert state, f"an Action history item has no actionState in its HistoryData: {item!r}"
    return state


def _drain(sqs, queue_url) -> None:
    """Empty the queue, so a later collection cannot count a message from an earlier beat."""
    while True:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not received:
            return
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]}
                for i, m in enumerate(received)
            ],
        )


def _collect(sqs, queue_url, *, into=None):
    """Receive and DELETE every available SNS envelope, returning {AlarmName: [payload, ...]}.

    Messages are deleted so a repeated call cannot double count, and accumulated into *into* so a
    poll that runs many times still sees everything that ever arrived. Every envelope must be an
    SNS Notification carrying a CloudWatch alarm payload -- an unexpected shape raises rather than
    being skipped, because a target that delivers the wrong envelope has diverged.
    """
    seen = {} if into is None else into
    while True:
        received = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            MessageAttributeNames=["All"],
        ).get("Messages", [])
        if not received:
            return seen
        for message in received:
            envelope = json.loads(message["Body"])
            assert envelope.get("Type") == "Notification", (
                f"expected an SNS Notification envelope on the queue, got Type "
                f"{envelope.get('Type')!r} in {envelope!r}"
            )
            payload = json.loads(envelope["Message"])
            name = payload.get("AlarmName")
            assert name, f"an alarm notification arrived with no AlarmName: {payload!r}"
            seen.setdefault(name, []).append(payload)
        sqs.delete_message_batch(
            QueueUrl=queue_url,
            Entries=[
                {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]}
                for i, m in enumerate(received)
            ],
        )


def _assert_stays_silent(
    sqs, queue_url, cw, suppressed_name, control_name, *, hold_s, latency_s, tick
):
    """Assert the suppressed composite delivers nothing for hold_s, on two observables.

    The window is calibrated against *latency_s*, the latency the unsuppressed twin needed on this
    exact wiring in this exact run -- never a bare sleep, and never a constant. The second
    observable is DescribeAlarmHistory(HistoryItemType='Action'): a queue read alone could in
    principle miss a message another consumer took, whereas the history is server-side and
    monotone. AWS records a 'Suppressed' entry there the instant withholding starts, so the
    check watches actionState, never list emptiness.

    *tick* re-publishes both metrics every iteration: the child alarm has
    TreatMissingData="notBreaching", so an evaluation range with no fresh datapoint reverts the child,
    and the composite watching it, to OK.
    """
    deadline = time.monotonic() + hold_s
    accumulated: dict = {}
    while True:
        tick()
        _collect(sqs, queue_url, into=accumulated)
        assert suppressed_name not in accumulated, (
            f"the suppressed composite delivered {accumulated[suppressed_name]!r} during the "
            f"{hold_s:.0f}s absence window, which is 2x the {latency_s:.0f}s its unsuppressed twin "
            f"needed on the same wiring in this run"
        )
        # The suppressed composite already carries earlier 'Suppressed' entries from beat 1, so the
        # list itself is never empty here; none of its entries may reach actionState=='Succeeded'
        # while the hold is in force.
        actions = _action_history(cw, suppressed_name)
        fired = [item for item in actions if _action_state(item) == "Succeeded"]
        assert not fired, (
            f"the suppressed composite recorded a Succeeded Action history item {fired!r} during "
            f"the {hold_s:.0f}s absence window; its ActionsSuppressor is in ALARM, so no action may "
            f"be invoked"
        )
        control_actions = _action_history(cw, control_name)
        assert control_actions, (
            f"the UNSUPPRESSED twin {control_name!r} has an EMPTY Action history while the absence "
            f"window is being held. The window is only meaningful if the same wiring demonstrably "
            f"invokes actions, so an empty control history means this check is measuring nothing"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(5.0)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
