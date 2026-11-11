"""set-alarm-state-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "set-alarm-state-transitions"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState drives a metric alarm through OK -> ALARM -> INSUFFICIENT_DATA and
    DescribeAlarms reflects each transition."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    for target in ("ALARM", "OK", "INSUFFICIENT_DATA"):
        cw.set_alarm_state(AlarmName=name, StateValue=target, StateReason=f"sim2real-{target}")
        state = _poll_until(
            lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"],
            lambda v: v == target,
            timeout_s=30.0,
            interval_s=2.0,
            what=f"alarm {name!r} to reach state {target!r}",
        )
        assert state == target, f"expected alarm state {target}, saw {state}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting for {what}, last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
