"""alarm-appears-in-describe-alarms-for-metric-after-create."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-appears-in-describe-alarms-for-metric-after-create"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metric alarm surfaces in DescribeAlarmsForMetric after PutMetricAlarm, and disappears after DeleteAlarms."""
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealBehav")
    metric_name = "RequestLatency"
    alarm_name = ctx.unique_name("sim2real-metricalarm-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    matches = _poll_for_alarm(cw, namespace, metric_name, alarm_name, present=True, timeout_s=30.0)
    assert len(matches) == 1, f"expected exactly 1 alarm on the metric, got {len(matches)}"
    alarm = matches[0]
    assert alarm["AlarmName"] == alarm_name, f"expected AlarmName {alarm_name!r}, got {alarm['AlarmName']!r}"
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected ComparisonOperator 'GreaterThanThreshold', got {alarm['ComparisonOperator']!r}"
    )
    assert alarm["Threshold"] == 80.0, f"expected Threshold 80.0, got {alarm['Threshold']!r}"
    assert alarm["Namespace"] == namespace, f"expected Namespace {namespace!r}, got {alarm['Namespace']!r}"
    assert alarm["MetricName"] == metric_name, f"expected MetricName {metric_name!r}, got {alarm['MetricName']!r}"

    cw.delete_alarms(AlarmNames=[alarm_name])

    remaining = _poll_for_alarm(cw, namespace, metric_name, alarm_name, present=False, timeout_s=30.0)
    assert remaining == [], f"alarm {alarm_name} still present in DescribeAlarmsForMetric after DeleteAlarms"


def _poll_for_alarm(cw, namespace, metric_name, alarm_name, present: bool, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name)["MetricAlarms"]
        last = [a for a in alarms if a["AlarmName"] == alarm_name]
        found = len(last) > 0
        if found == present:
            return last
        time.sleep(1)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for alarm {alarm_name!r} to be "
        f"{'present' if present else 'absent'} in DescribeAlarmsForMetric "
        f"(namespace={namespace!r}, metric={metric_name!r}); last observed={last}"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
