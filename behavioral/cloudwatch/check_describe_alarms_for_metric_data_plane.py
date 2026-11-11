"""describe-alarms-for-metric-data-plane."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-alarms-for-metric-data-plane"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric indexes alarms by their exact Namespace/MetricName/Dimensions
    triple, returning only alarms that watch that specific metric signature."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    dim_value = ctx.unique_name("host-")
    watched = ctx.unique_name("sim2real-behav-watched-")
    unrelated = ctx.unique_name("sim2real-behav-unrelated-")

    cw.put_metric_alarm(
        AlarmName=watched,
        MetricName="ForMetricCheck",
        Namespace=namespace,
        Dimensions=[{"Name": "Host", "Value": dim_value}],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    # A second alarm on a different metric must not show up in the lookup below.
    cw.put_metric_alarm(
        AlarmName=unrelated,
        MetricName="SomeOtherMetric",
        Namespace=namespace,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[watched, unrelated])))

    result = cw.describe_alarms_for_metric(
        Namespace=namespace,
        MetricName="ForMetricCheck",
        Dimensions=[{"Name": "Host", "Value": dim_value}],
    )["MetricAlarms"]

    names = {a["AlarmName"] for a in result}
    assert watched in names, f"expected {watched} in {names}"
    assert unrelated not in names, f"unrelated alarm leaked into metric-scoped lookup: {names}"
    assert names == {watched}, (
        f"expected exactly {{{watched!r}}} scoped to this namespace/metric/dimensions, got {names!r}"
    )

    cw.delete_alarms(AlarmNames=[watched, unrelated])
    remaining = cw.describe_alarms_for_metric(
        Namespace=namespace,
        MetricName="ForMetricCheck",
        Dimensions=[{"Name": "Host", "Value": dim_value}],
    )["MetricAlarms"]
    assert remaining == [], f"deleted alarm {watched} still present in metric-scoped lookup: {remaining}"


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
