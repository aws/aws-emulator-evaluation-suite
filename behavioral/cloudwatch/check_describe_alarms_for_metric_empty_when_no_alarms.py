"""describe-alarms-for-metric-empty-when-no-alarms."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-alarms-for-metric-empty-when-no-alarms"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns an empty list for a metric with no alarms, then
    reflects the alarm once PutMetricAlarm creates one on that metric, and returns to
    empty once the alarm is deleted."""
    cw = ctx.client("cloudwatch")
    namespace = "Sim2Real/Behavioral"
    metric_name = ctx.unique_name("DescribeForMetric-")

    before = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    assert before["MetricAlarms"] == [], f"expected no alarms yet, got {before['MetricAlarms']}"

    alarm_name = ctx.unique_name("sim2real-for-metric-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=42.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(cw, alarm_name))

    found = _poll_until(
        lambda: cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)["MetricAlarms"],
        lambda alarms: any(a["AlarmName"] == alarm_name for a in alarms),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert len(found) == 1, f"expected exactly one alarm on this metric, got {len(found)}"
    match = found[0]
    assert match["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected GreaterThanThreshold, got {match['ComparisonOperator']}"
    )
    assert match["Threshold"] == 42.0, f"expected threshold 42.0, got {match['Threshold']}"
    assert match["Statistic"] == "Average", f"expected statistic Average, got {match['Statistic']}"
    assert match["Period"] == 60, f"expected period 60, got {match['Period']}"
    assert match["EvaluationPeriods"] == 1, f"expected 1 evaluation period, got {match['EvaluationPeriods']}"

    # unrelated metrics still see no alarms
    other = cw.describe_alarms_for_metric(MetricName=ctx.unique_name("OtherMetric-"), Namespace=namespace)
    assert other["MetricAlarms"] == [], f"expected no alarms for an unrelated metric, got {other['MetricAlarms']}"

    cw.delete_alarms(AlarmNames=[alarm_name])
    after_delete = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    assert after_delete["MetricAlarms"] == [], (
        f"expected no alarms after delete, got {after_delete['MetricAlarms']}"
    )


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"condition not met within {timeout_s}s; last result: {result}")


def _safe_delete(cw, name):
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
