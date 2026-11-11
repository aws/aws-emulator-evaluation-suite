"""metric-alarm-manual-state-transition-history."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "metric-alarm-manual-state-transition-history"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState transitions StateValue and is recorded as StateUpdate history."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="DummyMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="forced-alarm-test")
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0],
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=30.0,
    )
    assert state is not None, "alarm never reflected forced ALARM state"
    assert state["StateReason"] == "forced-alarm-test", (
        f"expected StateReason 'forced-alarm-test', got {state['StateReason']!r}"
    )

    cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="forced-ok-test")
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0],
        lambda a: a["StateValue"] == "OK",
        timeout_s=30.0,
    )
    assert state is not None, "alarm never reflected forced OK state"
    assert state["StateReason"] == "forced-ok-test", (
        f"expected StateReason 'forced-ok-test', got {state['StateReason']!r}"
    )

    history = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate")
    items = history["AlarmHistoryItems"]
    assert len(items) >= 2, f"expected at least 2 StateUpdate history items, got {len(items)}"
    for item in items:
        assert item["HistoryItemType"] == "StateUpdate", (
            f"expected HistoryItemType 'StateUpdate', got {item['HistoryItemType']!r}"
        )
        assert item["AlarmName"] == name, (
            f"expected history item for alarm {name!r}, got {item['AlarmName']!r}"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
