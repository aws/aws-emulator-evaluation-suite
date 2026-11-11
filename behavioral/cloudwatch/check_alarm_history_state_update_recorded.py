"""alarm-history-state-update-recorded."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "alarm-history-state-update-recorded"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:metrics", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Forcing an alarm's state via SetAlarmState writes a StateUpdate entry into
    DescribeAlarmHistory that records the new state and the supplied reason."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="LatencyP99",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    reason = ctx.unique_name("sim2real-behav-reason-")
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=reason)

    def _history_items():
        resp = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate")
        return resp["AlarmHistoryItems"]

    items = _poll_until(_history_items, lambda i: len(i) >= 1, timeout_s=60, interval_s=3)
    # Real CloudWatch's HistorySummary is a fixed human-readable string (e.g. "Alarm updated
    # from OK to ALARM") that does not embed the caller-supplied StateReason text -- the
    # reason is instead recorded, verbatim, under HistoryData's newState.stateReason.
    parsed = [json.loads(item["HistoryData"]) for item in items]
    assert any(p.get("newState", {}).get("stateReason") == reason for p in parsed), (
        f"expected a StateUpdate history entry whose newState.stateReason equals our forced "
        f"reason {reason!r}, got {parsed}"
    )
    for item in items:
        assert item["HistoryItemType"] == "StateUpdate"
        assert item["AlarmName"] == name

    cw.delete_alarms(AlarmNames=[name])
    remaining = cw.describe_alarms(AlarmNames=[name]).get("MetricAlarms", [])
    assert remaining == [], f"expected alarm {name} to be gone after DeleteAlarms, got {remaining}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
