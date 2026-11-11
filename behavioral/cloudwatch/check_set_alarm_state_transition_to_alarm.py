"""set-alarm-state-transition-to-alarm."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "set-alarm-state-transition-to-alarm"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created alarm starts INSUFFICIENT_DATA (no data has ever been
    published), so SetAlarmState(ALARM) is a real state-machine transition, not
    just a value echoed back. DescribeAlarms reflects the new state and reason."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-owner", "Value": "check_set_alarm_state_transition_to_alarm"}],
    )

    initial = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert initial == "INSUFFICIENT_DATA", (
        f"expected a freshly created alarm to start INSUFFICIENT_DATA, got {initial!r}"
    )

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="forced by check",
    )

    def probe():
        return cw.describe_alarms(AlarmNames=[alarm_name])

    resp = _poll_until(
        probe,
        lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["StateValue"] == "ALARM",
        timeout_s=20,
        interval_s=2,
    )
    alarm = resp["MetricAlarms"][0]
    assert alarm["StateValue"] == "ALARM", (
        f"expected ALARM after SetAlarmState, got {alarm['StateValue']!r}"
    )
    assert alarm["StateReason"] == "forced by check", (
        f"expected StateReason 'forced by check', got {alarm['StateReason']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
