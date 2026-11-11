"""alarm-history-records-state-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-history-records-state-update"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory records a StateUpdate history item after SetAlarmState changes
    the alarm's state, with the reason text we supplied and the new state value, both
    carried in the item's structured HistoryData rather than the human-readable summary."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    reason = f"sim2real-history-marker-{ctx.unique_name('r')}"
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=reason)

    def probe():
        # Real CloudWatch's HistorySummary text for a StateUpdate item is a generic
        # "Alarm updated from X to Y" string -- it does not embed the caller-supplied
        # StateReason. The reason we passed is recorded in the item's HistoryData JSON
        # blob (under newState.stateReason) instead, so that's what we must parse and
        # match exactly -- a substring match could be satisfied by an unrelated field.
        items = cw.describe_alarm_history(
            AlarmName=name, HistoryItemType="StateUpdate", MaxRecords=50
        )["AlarmHistoryItems"]
        for item in items:
            try:
                data = json.loads(item.get("HistoryData", "{}"))
            except (TypeError, ValueError):
                continue
            if data.get("newState", {}).get("stateReason") == reason:
                return item
        return None

    match = _poll_until(probe, lambda m: m is not None, timeout_s=45.0, interval_s=3.0)
    data = json.loads(match["HistoryData"])
    assert data["newState"]["stateReason"] == reason, (
        f"expected the StateUpdate item's HistoryData.newState.stateReason to be "
        f"{reason!r}, got {data['newState'].get('stateReason')!r}"
    )
    assert data["newState"]["stateValue"] == "ALARM", (
        f"expected the StateUpdate item's HistoryData.newState.stateValue to be "
        f"'ALARM', got {data['newState'].get('stateValue')!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
