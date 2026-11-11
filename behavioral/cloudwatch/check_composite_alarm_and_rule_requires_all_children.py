"""composite-alarm-and-rule-requires-all-children."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-and-rule-requires-all-children"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm with an AND AlarmRule stays out of ALARM until every referenced
    child alarm is in ALARM, then transitions once the last one trips."""
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
        )
        cw.set_alarm_state(AlarmName=child, StateValue="OK", StateReason="init")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_a, child_b]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child_a}") AND ALARM("{child_b}")',
        ActionsEnabled=False,
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

    # Real CloudWatch can take up to roughly a minute to perform a composite alarm's
    # first evaluation after PutCompositeAlarm, during which DescribeAlarms may report
    # no StateValue transition yet (or the alarm may not even be visible immediately).
    # Give it the same generous window used below for the ALARM transition instead of
    # a tight 30s budget.
    state = _poll_until(composite_state, lambda v: v == "OK", timeout_s=90.0, interval_s=3.0)
    assert state == "OK", f"expected initial composite state OK, saw {state}"

    # Trip only one of the two required children: the composite must NOT enter ALARM.
    # Poll repeatedly across the observation window (instead of a single sleep-then-check)
    # so a transient flip to ALARM at any point during the window is caught, not just at
    # the end of it.
    cw.set_alarm_state(AlarmName=child_a, StateValue="ALARM", StateReason="trip-a-only")
    state = _poll_never(composite_state, forbidden="ALARM", timeout_s=45.0, interval_s=5.0)
    assert state != "ALARM", "composite entered ALARM with only one of two AND-ed children tripped"

    # Trip the second child too: the composite must now enter ALARM.
    cw.set_alarm_state(AlarmName=child_b, StateValue="ALARM", StateReason="trip-b-too")
    state = _poll_until(composite_state, lambda v: v == "ALARM", timeout_s=90.0, interval_s=3.0)
    assert state == "ALARM", f"composite did not transition to ALARM once both children tripped: {state}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _poll_never(probe, forbidden, timeout_s=45.0, interval_s=5.0):
    """Repeatedly poll probe() across a bounded window, asserting it never equals
    `forbidden`. Returns the last observed value once the window elapses."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    assert last != forbidden, f"unexpected transition to {forbidden!r} observed immediately"
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
        assert last != forbidden, f"unexpected transition to {forbidden!r} observed mid-poll"
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
