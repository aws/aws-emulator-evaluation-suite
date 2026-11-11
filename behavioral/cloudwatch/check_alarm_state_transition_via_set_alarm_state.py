"""alarm-state-transition-via-set-alarm-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-state-transition-via-set-alarm-state"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created metric alarm starts INSUFFICIENT_DATA, and SetAlarmState
    forces OK/ALARM/INSUFFICIENT_DATA transitions that are immediately observable
    via DescribeAlarms (no incoming metric data to override them)."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "team", "Value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    initial = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]
    assert initial == "INSUFFICIENT_DATA", f"expected INSUFFICIENT_DATA at creation, got {initial}"

    for target, reason in (
        ("OK", "sim2real test ok"),
        ("ALARM", "sim2real test alarm"),
        ("INSUFFICIENT_DATA", "sim2real test insufficient"),
    ):
        cw.set_alarm_state(AlarmName=name, StateValue=target, StateReason=reason)
        observed = _poll_state(ctx, name, target, timeout_s=15.0)
        assert observed == target, f"expected {target} after SetAlarmState, got {observed}"


def _poll_state(ctx, alarm_name: str, expected: str, timeout_s: float = 15.0, interval_s: float = 1.0) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if last == expected:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
