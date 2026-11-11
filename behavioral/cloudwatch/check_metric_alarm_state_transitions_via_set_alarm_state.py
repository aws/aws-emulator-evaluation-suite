"""metric-alarm-state-transitions-via-set-alarm-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "metric-alarm-state-transitions-via-set-alarm-state"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new metric alarm starts INSUFFICIENT_DATA and SetAlarmState forces
    ALARM/OK/INSUFFICIENT_DATA transitions, each independently observable via
    DescribeAlarms together with the StateReason that was set."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2Real-CW-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ErrorRate",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    initial = _poll_until(
        lambda: _get_alarm(cw, alarm_name),
        lambda a: a is not None,
        timeout_s=30.0,
        reason=f"alarm {alarm_name} never appeared in DescribeAlarms",
    )["StateValue"]
    assert initial == "INSUFFICIENT_DATA", (
        f"expected a freshly created alarm to start INSUFFICIENT_DATA, got {initial}"
    )

    for target, reason_text in (
        ("ALARM", "forced-alarm"),
        ("OK", "forced-ok"),
        ("INSUFFICIENT_DATA", "forced-insufficient"),
    ):
        cw.set_alarm_state(AlarmName=alarm_name, StateValue=target, StateReason=reason_text)
        alarm = _poll_until(
            lambda: _get_alarm(cw, alarm_name),
            lambda a: a is not None and a["StateValue"] == target,
            timeout_s=30.0,
            reason=f"alarm {alarm_name} never reached {target} after SetAlarmState",
        )
        assert alarm["StateValue"] == target, (
            f"expected state {target} after SetAlarmState, got {alarm['StateValue']}"
        )
        assert alarm["StateReason"] == reason_text, (
            f"expected StateReason {reason_text!r} to round-trip, got {alarm['StateReason']!r}"
        )


def _get_alarm(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    return alarms[0] if alarms else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, reason="condition not met"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{reason} within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
