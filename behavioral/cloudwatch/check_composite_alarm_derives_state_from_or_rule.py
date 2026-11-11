"""composite-alarm-derives-state-from-or-rule."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-derives-state-from-or-rule"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm with an OR AlarmRule transitions to ALARM as soon as one of its
    referenced child alarms enters ALARM, without the other child changing."""
    cw = ctx.client("cloudwatch")
    child_a = ctx.unique_name("sim2real-behav-child-a-")
    child_b = ctx.unique_name("sim2real-behav-child-b-")
    composite = ctx.unique_name("sim2real-behav-composite-")

    for child in (child_a, child_b):
        cw.put_metric_alarm(
            AlarmName=child,
            MetricName="Sim2RealMetric",
            Namespace="Sim2RealBehavioral",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        cw.set_alarm_state(AlarmName=child, StateValue="OK", StateReason="init")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_a, child_b]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child_a}") OR ALARM("{child_b}")',
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    def composite_state():
        # The composite alarm can take a moment to become visible via DescribeAlarms
        # right after PutCompositeAlarm; treat "not found yet" as None rather than
        # raising, and let the poll loop keep retrying.
        # Real CloudWatch's DescribeAlarms defaults to returning only metric alarms
        # when AlarmTypes is omitted -- composite alarms are silently excluded even
        # when their name is passed via AlarmNames. AlarmTypes must be given
        # explicitly to get the composite alarm's state back.
        alarms = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        return alarms[0]["StateValue"] if alarms else None

    composite_state_value = _poll_until(
        composite_state,
        lambda v: v == "OK",
        # Real CloudWatch can take up to roughly a minute to perform a composite alarm's
        # first evaluation after PutCompositeAlarm; a tight 30s budget flakes on real AWS,
        # so give it the same generous window used below for the ALARM transition.
        timeout_s=90.0,
        interval_s=3.0,
        description="composite alarm initial state OK",
    )
    assert composite_state_value == "OK", f"expected initial composite state OK, saw {composite_state_value}"


    cw.set_alarm_state(AlarmName=child_a, StateValue="ALARM", StateReason="trip-a")
    composite_state_value = _poll_until(
        composite_state,
        lambda v: v == "ALARM",
        timeout_s=90.0,
        interval_s=3.0,
        description="composite alarm ALARM transition from child_a alone (OR rule, child_b untouched)",
    )
    assert composite_state_value == "ALARM", f"composite did not transition to ALARM: {composite_state_value}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
