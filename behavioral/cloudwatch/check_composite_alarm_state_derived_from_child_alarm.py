"""composite-alarm-state-derived-from-child-alarm."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-state-derived-from-child-alarm"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm's StateValue tracks the boolean AlarmRule evaluated over its child alarm's state."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-child-")
    composite_name = ctx.unique_name("sim2real-composite-")
    namespace = ctx.unique_name("Sim2Real-CW-")

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace=namespace,
        MetricName="ChildMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    baseline = _get_state(cw, composite_name)
    assert baseline != "ALARM", f"composite alarm must not start ALARM before its child ever entered ALARM, got {baseline}"

    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="child-alarm")
    state = _poll_until(
        lambda: _get_state(cw, composite_name), lambda s: s == "ALARM", timeout_s=90.0
    )
    if state != "ALARM":
        raise AssertionError(
            "composite alarm never converged to ALARM within timeout",
        )
    assert state == "ALARM", f"expected composite alarm ALARM after child ALARM, got {state}"

    cw.set_alarm_state(AlarmName=child_name, StateValue="OK", StateReason="child-ok")
    state = _poll_until(lambda: _get_state(cw, composite_name), lambda s: s == "OK", timeout_s=90.0)
    if state != "OK":
        raise AssertionError(
            "composite alarm never converged back to OK within timeout",
        )
    assert state == "OK", f"expected composite alarm OK after child OK, got {state}"


def _get_state(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
    return alarms[0]["StateValue"] if alarms else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
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
