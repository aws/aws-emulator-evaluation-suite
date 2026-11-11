"""composite-alarm-state-derived-from-children."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-state-derived-from-children"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm's state is derived immediately from its AlarmRule expression."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-ns-")
    alarm_a = ctx.unique_name("sim2real-cw-child-a-")
    alarm_b = ctx.unique_name("sim2real-cw-child-b-")
    composite = ctx.unique_name("sim2real-cw-composite-")

    for name in (alarm_a, alarm_b):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=ns,
            MetricName="DummyMetric",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
        )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_a, alarm_b]))

    cw.set_alarm_state(AlarmName=alarm_a, StateValue="ALARM", StateReason="force-alarm")
    cw.set_alarm_state(AlarmName=alarm_b, StateValue="OK", StateReason="force-ok")
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_a])["MetricAlarms"][0]["StateValue"],
        lambda v: v == "ALARM",
        timeout_s=30.0,
    )

    rule = f'ALARM("{alarm_a}") OR ALARM("{alarm_b}")'
    cw.put_composite_alarm(AlarmName=composite, AlarmRule=rule)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])[
            "CompositeAlarms"
        ][0],
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=60.0,
    )
    assert state is not None, "composite alarm never derived ALARM state from ALARM(child_a) OR ALARM(child_b)"

    # Flip child A to OK, child B stays OK -> composite should transition away from ALARM.
    cw.set_alarm_state(AlarmName=alarm_a, StateValue="OK", StateReason="clear-alarm")
    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])[
            "CompositeAlarms"
        ][0],
        lambda a: a["StateValue"] == "OK",
        timeout_s=60.0,
    )
    assert state is not None, "composite alarm never re-derived OK state after children cleared"


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
