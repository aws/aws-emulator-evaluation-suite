"""describe-alarms-for-metric-server-computed-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-server-computed-list"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns exactly the set of alarms currently configured against a
    given metric/dimension signature -- computed server-side, not by the client aggregating
    DescribeAlarms output.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavNS")
    metric_name = "RequestLatency"
    dim_name = "Service"
    dim_value_a = ctx.unique_name("svc-a-")
    dim_value_b = ctx.unique_name("svc-b-")

    alarm_a1 = ctx.unique_name("sim2real-behav-alarm-a1-")
    alarm_a2 = ctx.unique_name("sim2real-behav-alarm-a2-")
    alarm_b1 = ctx.unique_name("sim2real-behav-alarm-b1-")

    for name, dim_value, threshold in (
        (alarm_a1, dim_value_a, 100),
        (alarm_a2, dim_value_a, 200),
        (alarm_b1, dim_value_b, 50),
    ):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dim_name, "Value": dim_value}],
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=threshold,
            ComparisonOperator="GreaterThanThreshold",
            Tags=[{"Key": "sim2real-owner", "Value": "cw-describe-alarms-for-metric-server-computed-list"}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    resp_a = cw.describe_alarms_for_metric(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": dim_name, "Value": dim_value_a}],
    )
    names_a = sorted(a["AlarmName"] for a in resp_a["MetricAlarms"])
    assert names_a == sorted([alarm_a1, alarm_a2]), f"unexpected alarm set for signature a: {names_a}"

    resp_b = cw.describe_alarms_for_metric(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": dim_name, "Value": dim_value_b}],
    )
    names_b = [a["AlarmName"] for a in resp_b["MetricAlarms"]]
    assert names_b == [alarm_b1], f"unexpected alarm set for signature b: {names_b}"

    # A metric/dimension signature with no configured alarms returns an empty, not an error.
    resp_none = cw.describe_alarms_for_metric(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": dim_name, "Value": ctx.unique_name("svc-none-")}],
    )
    assert resp_none["MetricAlarms"] == [], (
        f"expected no alarms for a dimension value with none configured, got {resp_none['MetricAlarms']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
