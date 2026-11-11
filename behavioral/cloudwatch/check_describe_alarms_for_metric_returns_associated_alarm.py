"""describe-alarms-for-metric-returns-associated-alarm."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-returns-associated-alarm"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns exactly the alarm(s) bound to that Namespace/MetricName, with matching config."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2Real-CW-")
    metric_name = "AssociatedMetric"

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Sum",
        Period=120,
        EvaluationPeriods=2,
        Threshold=7.5,
        ComparisonOperator="LessThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    resp = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    alarms = resp["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly 1 alarm for {namespace}/{metric_name}, got {alarms}"
    alarm = alarms[0]
    assert alarm["AlarmName"] == alarm_name, f"expected AlarmName {alarm_name!r}, got {alarm['AlarmName']!r}"
    assert alarm["Statistic"] == "Sum", f"expected Statistic 'Sum', got {alarm['Statistic']!r}"
    assert alarm["Period"] == 120, f"expected Period 120, got {alarm['Period']!r}"
    assert alarm["EvaluationPeriods"] == 2, f"expected EvaluationPeriods 2, got {alarm['EvaluationPeriods']!r}"
    assert alarm["Threshold"] == 7.5, f"expected Threshold 7.5, got {alarm['Threshold']!r}"
    assert alarm["ComparisonOperator"] == "LessThanThreshold", (
        f"expected ComparisonOperator 'LessThanThreshold', got {alarm['ComparisonOperator']!r}"
    )

    other_metric_resp = cw.describe_alarms_for_metric(MetricName="UnrelatedMetric-xyz", Namespace=namespace)
    assert other_metric_resp["MetricAlarms"] == [], (
        f"expected no alarms for unrelated metric name, got {other_metric_resp['MetricAlarms']}"
    )

    # The cleanup already deletes this alarm; make that delete a free negative assertion instead of
    # leaving it unproven.
    cw.delete_alarms(AlarmNames=[alarm_name])
    after_delete = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)["MetricAlarms"]
    assert after_delete == [], f"expected {alarm_name} to be gone after DeleteAlarms, got {after_delete}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
