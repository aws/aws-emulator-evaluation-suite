"""cloudwatch-alarm-state-transition-recorded."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-state-transition-recorded"
GROUP = "telemetry"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A CloudWatch alarm defined on an SQS queue metric transitions state when
    SetAlarmState is called, and the transition is durably recorded in the alarm's
    history (not just reflected transiently in DescribeAlarms)."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    queue_name = ctx.unique_name("sim2real-sqs-alarm-")
    url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    alarm_name = ctx.unique_name("sim2real-sqs-alarm-name-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/SQS",
        MetricName="ApproximateNumberOfMessagesVisible",
        Dimensions=[{"Name": "QueueName", "Value": queue_name}],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test forcing ALARM")
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=30.0,
    )

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="sim2real test forcing OK")
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "OK",
        timeout_s=30.0,
    )

    def _history_items():
        return cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=20
        )["AlarmHistoryItems"]

    history = _poll_until(_history_items, lambda items: len(items) >= 2, timeout_s=30.0)
    summaries = [h["HistorySummary"] for h in history]
    to_alarm = [h for h in history if "to ALARM" in h["HistorySummary"]]
    to_ok = [h for h in history if "to OK" in h["HistorySummary"]]
    assert to_alarm, f"no history entry recorded the transition to ALARM: {summaries!r}"
    assert to_ok, f"no history entry recorded the transition to OK: {summaries!r}"
    assert to_ok[0]["Timestamp"] > to_alarm[0]["Timestamp"], (
        f"OK transition not recorded after the ALARM transition: {summaries!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
