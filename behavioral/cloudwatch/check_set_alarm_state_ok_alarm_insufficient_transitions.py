"""set-alarm-state-ok-alarm-insufficient-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "set-alarm-state-ok-alarm-insufficient-transitions"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState forces the alarm StateValue through OK / ALARM / INSUFFICIENT_DATA
    and DescribeAlarms reflects each forced transition."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="RequestCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    def _state() -> str:
        resp = cw.describe_alarms(AlarmNames=[name])
        return resp["MetricAlarms"][0]["StateValue"]

    # A newly created alarm starts life in INSUFFICIENT_DATA.
    _poll_until(_state, lambda s: s == "INSUFFICIENT_DATA", timeout_s=30, interval_s=2)

    for target in ("ALARM", "OK", "INSUFFICIENT_DATA", "ALARM"):
        cw.set_alarm_state(AlarmName=name, StateValue=target, StateReason=f"forced-{target}")
        got = _poll_until(_state, lambda s, t=target: s == t, timeout_s=30, interval_s=2)
        assert got == target, f"expected alarm state {target}, saw {got}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
