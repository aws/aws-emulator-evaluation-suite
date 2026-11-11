"""describe-alarms-for-metric-association."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-association"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric finds alarms keyed by namespace/metric/dimensions/statistic."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "AssociatedMetric"
    name = ctx.unique_name("sim2real-cw-alarm-")
    dims = [{"Name": "Env", "Value": "prod"}]

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dims,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    matched = cw.describe_alarms_for_metric(
        MetricName=metric_name, Namespace=namespace, Dimensions=dims, Statistic="Average", Period=60
    )["MetricAlarms"]
    names = [a["AlarmName"] for a in matched]
    assert name in names, f"expected {name} in DescribeAlarmsForMetric results, got {names}"

    # A different dimension value must NOT match this alarm.
    mismatched = cw.describe_alarms_for_metric(
        MetricName=metric_name,
        Namespace=namespace,
        Dimensions=[{"Name": "Env", "Value": "dev"}],
        Statistic="Average",
        Period=60,
    )["MetricAlarms"]
    mismatched_names = [a["AlarmName"] for a in mismatched]
    assert name not in mismatched_names, (
        f"expected {name} to NOT match Dimensions=Env:dev, but got {mismatched_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
