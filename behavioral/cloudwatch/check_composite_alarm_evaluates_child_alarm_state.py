"""composite-alarm-evaluates-child-alarm-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-evaluates-child-alarm-state"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm re-evaluates its boolean AlarmRule whenever a child alarm's
    real state changes (SetAlarmState counts as a real change), transitioning to
    ALARM once ALARM(child) becomes true."""
    cw = ctx.client("cloudwatch")
    child = ctx.unique_name("sim2real-alarm-child-")
    composite = ctx.unique_name("sim2real-alarm-composite-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=child,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    # Register child cleanup FIRST so composite (registered second) is deleted
    # first at teardown (LIFO) -- otherwise deleting the child while referenced
    # by the composite's AlarmRule fails with ResourceConflict.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child}")',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    initial = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"][0][
        "StateValue"
    ]
    assert initial != "ALARM", f"composite should not start ALARM while child is not ALARM, got {initial}"

    cw.set_alarm_state(AlarmName=child, StateValue="ALARM", StateReason="sim2real composite test")

    final = _poll_composite_state(ctx, composite, "ALARM", timeout_s=90.0)
    assert final == "ALARM", f"composite alarm never transitioned to ALARM, last={final}"


def _poll_composite_state(ctx, alarm_name: str, expected: str, timeout_s: float, interval_s: float = 3.0) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        # DescribeAlarms only returns MetricAlarms unless AlarmTypes explicitly asks
        # for CompositeAlarms, even when filtering by an AlarmNames that names a
        # composite alarm.
        last = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"][0][
            "StateValue"
        ]
        if last == expected:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
