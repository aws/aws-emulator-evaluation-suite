"""describe-alarms-for-metric-scoped-to-namespace-dimensions."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-scoped-to-namespace-dimensions"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """DescribeAlarmsForMetric returns exactly the alarms matching namespace/metric/dimensions."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavDAFM")
    metric_name = "RequestLatency"
    dims_a = [{"Name": "Host", "Value": "host-a"}]
    dims_b = [{"Name": "Host", "Value": "host-b"}]

    alarm_a = ctx.unique_name("sim2real-behav-dafm-a-")
    alarm_b = ctx.unique_name("sim2real-behav-dafm-b-")
    alarm_c = ctx.unique_name("sim2real-behav-dafm-c-")
    all_alarms = [alarm_a, alarm_b, alarm_c]
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=all_alarms))

    common = dict(
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    # Same namespace + metric name, but a different dimension value.
    cw.put_metric_alarm(AlarmName=alarm_a, Namespace=namespace, MetricName=metric_name, Dimensions=dims_a, **common)
    cw.put_metric_alarm(AlarmName=alarm_b, Namespace=namespace, MetricName=metric_name, Dimensions=dims_b, **common)
    # Same namespace, but an entirely different metric name (no dimensions at all).
    cw.put_metric_alarm(AlarmName=alarm_c, Namespace=namespace, MetricName="UnrelatedMetric", **common)

    resp = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name, Dimensions=dims_a)
    returned_names = {a["AlarmName"] for a in resp["MetricAlarms"]}
    assert returned_names == {alarm_a}, (
        f"expected only {alarm_a!r} to match namespace={namespace!r} metric={metric_name!r} "
        f"dimensions={dims_a!r}, got {returned_names!r}"
    )

    # Sanity: the dimension-B alarm is discoverable under its own dimension value.
    resp_b = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name, Dimensions=dims_b)
    returned_names_b = {a["AlarmName"] for a in resp_b["MetricAlarms"]}
    assert returned_names_b == {alarm_b}, (
        f"expected only {alarm_b!r} to match dimensions={dims_b!r}, got {returned_names_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
