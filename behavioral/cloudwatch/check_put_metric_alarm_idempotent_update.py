"""put-metric-alarm-idempotent-update."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "put-metric-alarm-idempotent-update"
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
    """Re-issuing PutMetricAlarm for the same AlarmName updates config in place (create-or-update)."""
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
    )
    first = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert first["Threshold"] == 1.0, f"expected initial threshold 1.0, got {first['Threshold']}"

    # Update the same alarm name with a different threshold - must overwrite, not conflict.
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
    )

    def probe():
        return cw.describe_alarms(AlarmNames=[alarm_name])

    resp = _poll_until(
        probe, lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["Threshold"] == 99.0,
        timeout_s=20, interval_s=2,
    )
    updated = resp["MetricAlarms"][0]
    assert updated["Threshold"] == 99.0, f"expected updated threshold 99.0, got {updated['Threshold']}"
    assert len(resp["MetricAlarms"]) == 1, "update must not create a second alarm"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
