"""alarm-actions-enable-disable."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "alarm-actions-enable-disable"
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
    """DisableAlarmActions/EnableAlarmActions toggle ActionsEnabled without touching alarm state."""
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
        ActionsEnabled=True,
        Tags=[{"Key": "sim2real-behavioral", "Value": "alarm-actions-enable-disable"}],
    )

    def probe():
        return cw.describe_alarms(AlarmNames=[alarm_name])

    state_before = probe()["MetricAlarms"][0]["StateValue"]

    cw.disable_alarm_actions(AlarmNames=[alarm_name])

    resp = _poll_until(
        probe, lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["ActionsEnabled"] is False,
        timeout_s=20, interval_s=2, description="ActionsEnabled to flip False after DisableAlarmActions",
    )
    alarm = resp["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is False, f"expected ActionsEnabled False, got {alarm['ActionsEnabled']!r}"
    assert alarm["StateValue"] == state_before, (
        f"disabling actions must not change StateValue: expected {state_before!r}, got {alarm['StateValue']!r}"
    )

    cw.enable_alarm_actions(AlarmNames=[alarm_name])
    resp = _poll_until(
        probe, lambda r: r["MetricAlarms"] and r["MetricAlarms"][0]["ActionsEnabled"] is True,
        timeout_s=20, interval_s=2, description="ActionsEnabled to flip True after EnableAlarmActions",
    )
    alarm = resp["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is True, f"expected ActionsEnabled True, got {alarm['ActionsEnabled']!r}"
    assert alarm["StateValue"] == state_before, (
        f"enabling actions must not change StateValue: expected {state_before!r}, got {alarm['StateValue']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
