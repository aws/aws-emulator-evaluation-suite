"""alarm-history-records-state-updates-in-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-history-records-state-updates-in-order"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory records each SetAlarmState transition, newest first, with the exact StateReason."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2Real-CW-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="QueueDepth",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        # The metric is never published; 'ignore' keeps each forced state, so the evaluator adds
        # no StateUpdate of its own between or after the three below.
        TreatMissingData="ignore",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="reason-1")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="reason-2")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="reason-3")

    items = _poll_until(
        lambda: cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
        )["AlarmHistoryItems"],
        lambda its: len(its) >= 3,
        timeout_s=60.0,
    )
    if len(items) < 3:
        raise AssertionError("alarm history did not record all 3 transitions within timeout")

    top3 = items[:3]
    for item in top3:
        assert item["HistoryItemType"] == "StateUpdate", (
            f"expected only StateUpdate items from the HistoryItemType filter, got {item['HistoryItemType']!r}"
        )
        assert item["AlarmName"] == alarm_name, (
            f"expected only {alarm_name!r} items from the AlarmName filter, got {item['AlarmName']!r}"
        )

    reasons = [json.loads(item["HistoryData"])["newState"]["stateReason"] for item in top3]
    assert reasons == ["reason-3", "reason-2", "reason-1"], (
        f"expected newest-first StateReason order ['reason-3', 'reason-2', 'reason-1'], got {reasons}"
    )

    new_values = [json.loads(item["HistoryData"])["newState"]["stateValue"] for item in top3]
    assert new_values == ["ALARM", "OK", "ALARM"], (
        f"expected newest-first StateValue order ['ALARM', 'OK', 'ALARM'], got {new_values}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
