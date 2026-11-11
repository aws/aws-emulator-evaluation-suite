"""composite-alarm-boolean-and-logic."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-boolean-and-logic"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm with an AND rule over two children only alarms once BOTH
    children are in ALARM -- one child alone must not trip it."""
    cw = ctx.client("cloudwatch")
    a = ctx.unique_name("sim2real-alarm-a-")
    b = ctx.unique_name("sim2real-alarm-b-")
    composite = ctx.unique_name("sim2real-alarm-and-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}]

    for child in (a, b):
        cw.put_metric_alarm(
            AlarmName=child,
            Namespace=namespace,
            MetricName="InvocationCount",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            Tags=tags_kv,
        )
        ctx.on_cleanup(lambda c=child: cw.delete_alarms(AlarmNames=[c]))

    cw.put_composite_alarm(AlarmName=composite, AlarmRule=f'ALARM("{a}") AND ALARM("{b}")', Tags=tags_kv)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    # DescribeAlarms can take a moment to surface a just-created composite alarm, so an
    # immediate read can race an empty CompositeAlarms list -- that means "not visible
    # yet", not "no such alarm", so poll for visibility instead of hard-indexing.
    initial = _poll_composite_state(ctx, composite, expected=None, timeout_s=30.0, stop_when_visible=True)
    assert initial is not None, f"composite alarm {composite} never became visible via DescribeAlarms"
    assert initial != "ALARM", f"composite AND-rule should not start ALARM, got {initial}"

    cw.set_alarm_state(AlarmName=a, StateValue="ALARM", StateReason="sim2real and-logic single child")
    still_not_alarm = _poll_composite_state(ctx, composite, "ALARM", timeout_s=20.0)
    assert still_not_alarm != "ALARM", "composite AND-rule tripped with only one of two children in ALARM"

    cw.set_alarm_state(AlarmName=b, StateValue="ALARM", StateReason="sim2real and-logic second child")
    final = _poll_composite_state(ctx, composite, "ALARM", timeout_s=90.0)
    assert final == "ALARM", f"composite AND-rule never became ALARM once both children alarmed, last={final}"


def _poll_composite_state(
    ctx, alarm_name: str, expected, timeout_s: float, interval_s: float = 3.0, stop_when_visible: bool = False
):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        # DescribeAlarms only returns MetricAlarms unless AlarmTypes explicitly asks for
        # CompositeAlarms, even when filtering by an AlarmNames that names a composite
        # alarm -- and a just-created composite alarm can also be briefly absent from
        # that list, which means "not visible yet", not "no such alarm".
        alarms = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        last = alarms[0]["StateValue"] if alarms else None
        if last == expected or (stop_when_visible and last is not None):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
