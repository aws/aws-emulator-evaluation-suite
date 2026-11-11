"""describe-alarms-for-metric-reflects-attached-alarms."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-alarms-for-metric-reflects-attached-alarms"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns exactly the alarms currently bound to a metric+dimension
    set, and updates live as alarms are added/removed."""
    cw = ctx.client("cloudwatch")

    namespace = "Sim2RealBehavioral"
    metric_name = ctx.unique_name("sim2real-dafm-metric-")
    dimensions = [{"Name": "Host", "Value": ctx.unique_name("host-")}]

    alarm_a = ctx.unique_name("sim2real-dafm-a-")
    alarm_b = ctx.unique_name("sim2real-dafm-b-")

    def _put(name):
        cw.put_metric_alarm(
            AlarmName=name,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            MetricName=metric_name,
            Namespace=namespace,
            Dimensions=dimensions,
            Period=60,
            Statistic="Average",
            Threshold=100.0,
            ActionsEnabled=False,
        )

    # Baseline: no alarms yet on this brand-new metric/dimension combination.
    baseline = cw.describe_alarms_for_metric(
        MetricName=metric_name, Namespace=namespace, Dimensions=dimensions
    )
    assert baseline["MetricAlarms"] == [], f"expected no alarms yet, got {baseline['MetricAlarms']}"

    _put(alarm_a)
    ctx.on_cleanup(lambda: _safe_delete_alarm(cw, alarm_a))
    _put(alarm_b)
    ctx.on_cleanup(lambda: _safe_delete_alarm(cw, alarm_b))

    with_both = cw.describe_alarms_for_metric(
        MetricName=metric_name, Namespace=namespace, Dimensions=dimensions
    )
    names_with_both = {a["AlarmName"] for a in with_both["MetricAlarms"]}
    assert names_with_both == {alarm_a, alarm_b}, f"expected both alarms, got {names_with_both}"

    # A different, unrelated dimension value must not show up here.
    other_dim_result = cw.describe_alarms_for_metric(
        MetricName=metric_name,
        Namespace=namespace,
        Dimensions=[{"Name": "Host", "Value": ctx.unique_name("other-host-")}],
    )
    assert other_dim_result["MetricAlarms"] == [], "unrelated dimension value must not match these alarms"

    cw.delete_alarms(AlarmNames=[alarm_a])

    after_delete = cw.describe_alarms_for_metric(
        MetricName=metric_name, Namespace=namespace, Dimensions=dimensions
    )
    names_after_delete = {a["AlarmName"] for a in after_delete["MetricAlarms"]}
    assert names_after_delete == {alarm_b}, f"expected only {alarm_b} to remain, got {names_after_delete}"


def _safe_delete_alarm(cw, name):
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
