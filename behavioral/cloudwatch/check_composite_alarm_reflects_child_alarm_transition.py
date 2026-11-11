"""composite-alarm-reflects-child-alarm-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-alarm-reflects-child-alarm-transition"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A composite alarm's StateValue transitions to ALARM once its referenced child alarm does."""
    cw = ctx.client("cloudwatch")
    child_name = ctx.unique_name("sim2real-cw-child-")
    composite_name = ctx.unique_name("sim2real-cw-composite-")

    cw.put_metric_alarm(
        AlarmName=child_name,
        Namespace="Sim2RealBehavioral",
        MetricName="ChildMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=50.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[child_name]))

    cw.put_composite_alarm(
        AlarmName=composite_name,
        AlarmRule=f'ALARM("{child_name}")',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_name]))

    # A brand-new composite alarm starts at INSUFFICIENT_DATA, but on real AWS
    # the composite is evaluated against its (also brand-new, dataless) child
    # almost immediately: ALARM("child") is FALSE while the child is anything
    # other than ALARM, so the composite can settle straight to OK before we
    # ever observe it. Either is a legitimate pre-trigger baseline; only
    # "already ALARM" would invalidate the transition test below.
    baseline = _describe_composite_state(cw, composite_name)
    assert baseline in ("INSUFFICIENT_DATA", "OK"), (
        f"expected new composite to start INSUFFICIENT_DATA or OK (pre-trigger), got {baseline}"
    )

    cw.set_alarm_state(AlarmName=child_name, StateValue="ALARM", StateReason="force-child-alarm")

    final_state = _poll_until(
        lambda: _describe_composite_state(cw, composite_name),
        lambda s: s == "ALARM",
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert final_state == "ALARM", f"composite alarm never transitioned to ALARM, last seen {final_state}"


def _describe_composite_state(cw, name):
    resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])
    alarms = resp["CompositeAlarms"]
    return alarms[0]["StateValue"] if alarms else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
