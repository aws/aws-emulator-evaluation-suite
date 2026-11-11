"""put-metric-alarm-initial-state-insufficient-data."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "put-metric-alarm-initial-state-insufficient-data"
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
    """A freshly created metric alarm with no data starts in INSUFFICIENT_DATA."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    def probe():
        return cw.describe_alarms(AlarmNames=[alarm_name])

    resp = _poll_until(probe, lambda r: len(r.get("MetricAlarms", [])) > 0, timeout_s=20, interval_s=2)
    alarms = resp["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm named {alarm_name!r}, got {alarms!r}"
    alarm = alarms[0]
    assert alarm["StateValue"] == "INSUFFICIENT_DATA", (
        f"expected initial state INSUFFICIENT_DATA, got {alarm['StateValue']}"
    )
    assert alarm["ActionsEnabled"] is True, (
        f"expected ActionsEnabled to default to True, got {alarm['ActionsEnabled']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
