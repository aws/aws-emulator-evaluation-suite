"""describe-alarms-for-metric-reflects-created-alarm."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-reflects-created-alarm"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns a new alarm (name, Threshold, ComparisonOperator, Period) for
    its exact metric without any data published, not for another metric in the namespace, and not
    at all once the alarm is deleted."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-dafm-")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "DescribeForMetricTest"
    other_metric_name = "DescribeForMetricTest-unrelated"

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    resp = cw.describe_alarms_for_metric(
        Namespace=namespace, MetricName=metric_name, Statistic="Average", Period=60
    )
    alarms = resp["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly 1 alarm for {namespace}/{metric_name}, got {alarms}"
    alarm = alarms[0]
    assert alarm["AlarmName"] == alarm_name, alarm
    assert alarm["Threshold"] == 1.0, alarm
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", alarm
    assert alarm["Period"] == 60, alarm

    unrelated = cw.describe_alarms_for_metric(
        Namespace=namespace, MetricName=other_metric_name, Statistic="Average", Period=60
    )
    assert unrelated["MetricAlarms"] == [], (
        f"DescribeAlarmsForMetric leaked {alarm_name} onto an unrelated metric: "
        f"{unrelated['MetricAlarms']}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    after_delete = cw.describe_alarms_for_metric(
        Namespace=namespace, MetricName=metric_name, Statistic="Average", Period=60
    )
    assert after_delete["MetricAlarms"] == [], (
        f"alarm {alarm_name} still present in DescribeAlarmsForMetric after DeleteAlarms: "
        f"{after_delete['MetricAlarms']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
