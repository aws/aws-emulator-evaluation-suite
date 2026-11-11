"""alarms-for-metric-reflects-created-alarms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarms-for-metric-reflects-created-alarms"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric links a metric back to the metric alarm that was
    created for it, with matching comparison/threshold configuration, and excludes
    an alarm created against a different metric name in the same namespace."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    other_name = ctx.unique_name("sim2real-alarm-other-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "ForMetricValue"
    other_metric_name = "UnrelatedMetricValue"

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=5.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    # A second alarm on a different metric in the same namespace: without this,
    # a target that returns every alarm in the namespace (ignoring MetricName)
    # would still pass, since the check only ever looked for its own alarm by name.
    cw.put_metric_alarm(
        AlarmName=other_name,
        Namespace=namespace,
        MetricName=other_metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="LessThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name, other_name]))

    resp = cw.describe_alarms_for_metric(
        Namespace=namespace, MetricName=metric_name, Statistic="Average", Period=60
    )
    returned_names = {a["AlarmName"] for a in resp["MetricAlarms"]}
    assert returned_names == {name}, (
        f"expected exactly {{{name!r}}} for namespace={namespace!r} "
        f"metric={metric_name!r}, got {returned_names!r}"
    )
    alarm = resp["MetricAlarms"][0]
    assert alarm["Threshold"] == 5.0, f"expected Threshold=5.0, got {alarm['Threshold']}"
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected ComparisonOperator=GreaterThanThreshold, got {alarm['ComparisonOperator']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
