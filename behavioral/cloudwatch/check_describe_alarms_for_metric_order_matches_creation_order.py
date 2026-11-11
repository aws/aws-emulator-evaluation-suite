"""describe-alarms-for-metric-order-matches-creation-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-order-matches-creation-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns the three alarms on one metric, created out of
    alphabetical order (C, A, B), in the same order on three repeated calls."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-dafm-ns-")
    metric_name = ctx.unique_name("sim2real-cw-dafm-metric-")

    # Created in a deliberately non-alphabetical sequence: C, A, B.
    alarm_c = ctx.unique_name("sim2real-cw-dafm-alarm-c-")
    alarm_a = ctx.unique_name("sim2real-cw-dafm-alarm-a-")
    alarm_b = ctx.unique_name("sim2real-cw-dafm-alarm-b-")

    for alarm_name in (alarm_c, alarm_a, alarm_b):
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=100.0,
            ComparisonOperator="GreaterThanThreshold",
        )
        ctx.on_cleanup(lambda n=alarm_name: cw.delete_alarms(AlarmNames=[n]))

    first = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    first_order = [a["AlarmName"] for a in first["MetricAlarms"]]
    second = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    second_order = [a["AlarmName"] for a in second["MetricAlarms"]]
    third = cw.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
    third_order = [a["AlarmName"] for a in third["MetricAlarms"]]

    assert set(first_order) == {alarm_c, alarm_a, alarm_b}, (
        f"expected all 3 alarms to be returned, got {first_order}"
    )
    assert first_order == second_order == third_order, (
        f"DescribeAlarmsForMetric order changed across repeated calls: "
        f"{first_order} vs {second_order} vs {third_order}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
