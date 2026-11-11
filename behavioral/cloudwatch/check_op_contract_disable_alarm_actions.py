"""op-contract-disableAlarmActions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-disableAlarmActions"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAlarmActions flips ActionsEnabled to false on the named alarm(s); AWS documents
    no error responses for this operation at all, and an unknown alarm name in the batch is
    silently accepted (no exception, no alarm created) rather than rejected."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-alarm-")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    bogus_name = ctx.unique_name("sim2real-cw-alarm-missing-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ErrorCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    before = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert before["ActionsEnabled"] is True, (
        f"expected ActionsEnabled=True before disable, got {before['ActionsEnabled']!r}"
    )

    # No exception for a batch that also names a nonexistent alarm; the call is a
    # documented no-op for the unknown name, and must not block the known one.
    cw.disable_alarm_actions(AlarmNames=[alarm_name, bogus_name])

    after = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0],
        lambda a: a["ActionsEnabled"] is False,
        timeout_s=20,
    )
    assert after["ActionsEnabled"] is False, (
        f"expected ActionsEnabled=False after disable, got {after['ActionsEnabled']!r}"
    )

    described = cw.describe_alarms(AlarmNames=[bogus_name])
    assert described["MetricAlarms"] == [] and described["CompositeAlarms"] == [], (
        "DisableAlarmActions naming an unknown alarm in the same batch must not create an alarm"
    )


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
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
