"""describe-alarm-history-chronological-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-alarm-history-chronological-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory returns StateUpdate history items for repeated SetAlarmState
    transitions in strict reverse-chronological order (newest first), matching the actual
    sequence of transitions we drove."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-histalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real/behav/"),
        MetricName="HistoryProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    transitions = ["ALARM", "OK", "ALARM", "OK", "INSUFFICIENT_DATA"]
    for idx, state in enumerate(transitions):
        cw.set_alarm_state(
            AlarmName=alarm_name,
            StateValue=state,
            StateReason=f"sim2real-behav transition #{idx}: -> {state}",
        )
        time.sleep(1.5)  # keep transitions timestamp-distinguishable

    items = _poll_for_history(ctx, alarm_name, expected_count=len(transitions), timeout_s=60.0)

    # 1) strict reverse-chronological order across everything returned
    timestamps = [item["Timestamp"] for item in items]
    for earlier, later in zip(timestamps, timestamps[1:]):
        assert earlier > later, f"history not in strict reverse-chronological order: {timestamps}"

    # 2) the newest len(transitions) items correspond exactly to our transitions, reversed
    observed_states = []
    for item in items[: len(transitions)]:
        data = json.loads(item["HistoryData"])
        observed_states.append(data["newState"]["stateValue"])
    expected_states = list(reversed(transitions))
    assert observed_states == expected_states, (
        f"history state sequence mismatch: observed={observed_states} expected={expected_states}"
    )


def _poll_for_history(ctx, alarm_name: str, expected_count: int, timeout_s: float = 60.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    items: list[dict] = []
    while time.monotonic() < deadline:
        resp = cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=50
        )
        items = resp["AlarmHistoryItems"]
        if len(items) >= expected_count:
            return items
        time.sleep(2)
    raise AssertionError(f"expected >= {expected_count} StateUpdate history items, got {len(items)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
