"""metric-alarm-state-transitions-recorded-in-history."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-alarm-state-transitions-recorded-in-history"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState forces StateValue and DescribeAlarmHistory records each StateUpdate."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="RequestLatency",
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
        StateReason="forced-to-alarm-for-behavioral-check",
    )
    _wait_for_alarm_state(cw, alarm_name, "ALARM", timeout_s=30)

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="OK",
        StateReason="forced-back-to-ok-for-behavioral-check",
    )
    _wait_for_alarm_state(cw, alarm_name, "OK", timeout_s=30)

    history = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate"
    )["AlarmHistoryItems"]
    assert len(history) >= 2, f"expected at least 2 StateUpdate history items, got {len(history)}"
    by_new_state = {}
    for item in history:
        assert item["HistoryItemType"] == "StateUpdate", item["HistoryItemType"]
        assert item["AlarmName"] == alarm_name, item["AlarmName"]
        new_state = json.loads(item["HistoryData"])["newState"]["stateValue"]
        by_new_state.setdefault(new_state, item["Timestamp"])
    assert "ALARM" in by_new_state, (
        f"no history item recorded the forced transition to ALARM: {list(by_new_state)}"
    )
    assert "OK" in by_new_state, (
        f"no history item recorded the forced transition to OK: {list(by_new_state)}"
    )
    assert by_new_state["OK"] > by_new_state["ALARM"], (
        f"OK transition ({by_new_state['OK']}) was not recorded after "
        f"the ALARM transition ({by_new_state['ALARM']})"
    )


def _wait_for_alarm_state(cw, alarm_name, expected, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"])
        alarms = resp["MetricAlarms"]
        if alarms:
            last = alarms[0]["StateValue"]
            if last == expected:
                return last
        time.sleep(interval_s)
    raise TimeoutError(
        f"alarm {alarm_name} did not reach state {expected!r} within {timeout_s}s "
        f"(last observed: {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
