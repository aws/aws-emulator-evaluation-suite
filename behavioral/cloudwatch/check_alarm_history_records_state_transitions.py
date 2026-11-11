"""alarm-history-records-state-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-history-records-state-transitions"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState-driven transitions are durably recorded as StateUpdate entries
    in DescribeAlarmHistory, with the summary reflecting the new state."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="sim2real history ok")
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real history alarm")

    items = _poll_history(ctx, name, min_count=2, timeout_s=30.0)
    assert len(items) >= 2, f"expected at least 2 StateUpdate history items, got {len(items)}"
    for item in items:
        assert item["HistoryItemType"] == "StateUpdate", (
            f"expected HistoryItemType StateUpdate, got {item['HistoryItemType']!r}"
        )
        assert item["AlarmName"] == name, f"expected history entry for {name!r}, got {item['AlarmName']!r}"
    latest = items[0]  # DescribeAlarmHistory returns most-recent-first
    assert "ALARM" in latest["HistorySummary"], (
        f"expected latest HistorySummary to mention the new ALARM state, got {latest['HistorySummary']!r}"
    )
    previous = items[1]
    assert "OK" in previous["HistorySummary"], (
        f"expected the preceding StateUpdate's HistorySummary to mention the OK state, "
        f"got {previous['HistorySummary']!r}"
    )


def _poll_history(ctx, alarm_name: str, min_count: int, timeout_s: float = 30.0, interval_s: float = 2.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=20
        )["AlarmHistoryItems"]
        if len(last) >= min_count:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
