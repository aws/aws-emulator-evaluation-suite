"""set-alarm-state-updates-state-and-history."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "set-alarm-state-updates-state-and-history"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState forces the alarm's StateValue directly and the transition is
    recorded as a StateUpdate entry in DescribeAlarmHistory."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cw-setstate-")
    namespace = "Sim2Real/BehavioralCheck"
    metric_name = ctx.unique_name("SetStateMetric-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="behavioral-check forced transition",
        StateReasonData='{"triggeredBy": "sim2real-behavioral-check"}',
    )

    state = _poll_alarm_state(cw, alarm_name, "ALARM", timeout_s=30.0)

    history = _poll_history(cw, alarm_name, timeout_s=30.0)
    latest = history[0]
    assert latest["HistoryItemType"] == "StateUpdate", (
        f"expected latest history item type 'StateUpdate', got {latest['HistoryItemType']!r}"
    )
    assert "ALARM" in latest["HistorySummary"], (
        f"expected 'ALARM' to appear in HistorySummary, got {latest['HistorySummary']!r} "
        f"(alarm state is {state!r})"
    )


def _poll_alarm_state(cw, alarm_name: str, expected: str, timeout_s: float, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])
        if alarms:
            last = alarms[0]["StateValue"]
            if last == expected:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"alarm {alarm_name!r} did not reach state {expected!r} within {timeout_s}s "
        f"(last observed: {last!r})"
    )


def _poll_history(cw, alarm_name: str, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate"
        ).get("AlarmHistoryItems", [])
        if items:
            return items
        time.sleep(interval_s)
    raise AssertionError(
        f"no StateUpdate history item recorded for alarm {alarm_name!r} within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
