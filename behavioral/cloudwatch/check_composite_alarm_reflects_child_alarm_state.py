"""composite-alarm-reflects-child-alarm-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-reflects-child-alarm-state"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm whose AlarmRule is ALARM(child) transitions to ALARM shortly after the
    child alarm's state is forced to ALARM, proving the composite is actually re-evaluated
    against the child's state rather than being an inert label."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-behav-compchild-")
    composite_name = ctx.unique_name("sim2real-behav-compparent-")
    namespace = ctx.unique_name("Sim2RealBehav/")

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    # Registered after the child cleanup, so LIFO teardown deletes the composite alarm
    # BEFORE the child it references (deleting the child first would be rejected).
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    def read_composite_state():
        # Real CloudWatch's DescribeAlarms defaults to returning only metric alarms when
        # AlarmTypes is omitted -- composite alarms are silently excluded even when their
        # name is passed via AlarmNames. AlarmTypes must be given explicitly to get the
        # composite alarm's current derived StateValue back.
        resp = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])
        composites = resp["CompositeAlarms"]
        return composites[0]["StateValue"] if composites else None

    baseline = read_composite_state()
    # A brand-new composite alarm with an unsatisfied AlarmRule must not already read as
    # ALARM. Without this, a target that always reports ALARM for any composite -- never
    # actually evaluating the rule against the child -- would still pass the assertion
    # below, since it only checks the state AFTER the child is forced to ALARM.
    assert baseline != "ALARM", (
        f"composite alarm already reads ALARM before its child was ever forced ALARM: {baseline!r}"
    )

    marker = ctx.unique_name("composite-trigger-")
    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason=marker)

    def saw_alarm(state):
        return state == "ALARM"

    # Real CloudWatch re-evaluates a composite alarm's AlarmRule asynchronously against
    # its children (it is not a synchronous side effect of SetAlarmState); that evaluation
    # cycle normally lands within roughly a minute, so a 90s budget is generous.
    # Newly-created composite alarms can also take a few seconds to become visible via
    # DescribeAlarms; read_composite_state's None return treats "not there yet" as "not in
    # the target state yet" so the poll keeps retrying instead of crashing on an empty list.
    state = _poll_until(read_composite_state, saw_alarm, timeout_s=90.0, interval_s=3.0)
    assert saw_alarm(state), (
        f"composite alarm never transitioned to ALARM after child was forced ALARM: {state!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
