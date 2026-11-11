"""e2e-composite-alarm-cascade-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-composite-alarm-cascade-lifecycle"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """SetAlarmState ALARM on one child of an OR composite moves the composite to ALARM, with a
    StateUpdate history item recording the transition, and DeleteAlarms removes all three alarms."""
    cw = ctx.client("cloudwatch")

    child1 = ctx.unique_name("sim2real-calarm-child1-")
    child2 = ctx.unique_name("sim2real-calarm-child2-")
    composite = ctx.unique_name("sim2real-calarm-composite-")
    namespace = ctx.unique_name("Sim2Real/CompositeAlarm")

    for name in (child1, child2):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName="DummyMetric",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [child1, child2]))

    alarm_rule = f'ALARM("{child1}") OR ALARM("{child2}")'
    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=alarm_rule,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_alarms_ignore(cw, [composite]))

    cw.set_alarm_state(AlarmName=child1, StateValue="ALARM", StateReason="sim2real forced alarm")

    def _composite_state():
        resp = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])
        return resp["CompositeAlarms"][0]["StateValue"]

    state = _poll_until(_composite_state, lambda s: s == "ALARM", timeout_s=90, interval_s=3)
    assert state == "ALARM", f"expected composite alarm to cascade to ALARM, last observed {state!r}"

    history = cw.describe_alarm_history(
        AlarmName=composite, HistoryItemType="StateUpdate", AlarmTypes=["CompositeAlarm"]
    )["AlarmHistoryItems"]
    to_alarm = [
        item
        for item in history
        if json.loads(item["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
    ]
    assert to_alarm, (
        f"expected a StateUpdate history entry recording the composite's transition to ALARM, "
        f"got {len(history)} StateUpdate entries: {[item.get('HistorySummary') for item in history]}"
    )

    cw.delete_alarms(AlarmNames=[composite])

    def _composite_gone():
        resp = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])
        return len(resp["CompositeAlarms"])

    _poll_until(_composite_gone, lambda n: n == 0, timeout_s=30)

    cw.delete_alarms(AlarmNames=[child1, child2])

    def _remaining():
        resp = cw.describe_alarms(AlarmNames=[composite, child1, child2])
        return len(resp["CompositeAlarms"]) + len(resp["MetricAlarms"])

    remaining = _poll_until(_remaining, lambda n: n == 0, timeout_s=30)
    assert remaining == 0, f"expected all 3 alarms (composite + 2 children) gone after delete, {remaining} remain"


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last={last!r}")


def _delete_alarms_ignore(cw, names):
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
