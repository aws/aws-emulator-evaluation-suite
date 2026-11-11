"""describe-alarms-for-metric-ordering-by-creation-time."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-ordering-by-creation-time"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns the same ordering of alarms across repeated
    calls when the underlying set of alarms on that metric is unchanged."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-dafm-ns-")
    metric_name = "RequestLatency"
    dim_value = ctx.unique_name("dim-")
    dimensions = [{"Name": "Case", "Value": dim_value}]

    # Create alarms in an order that is neither alphabetical nor reverse-alphabetical,
    # so that a stable-but-non-obvious sort key would still be caught if it varied.
    alarm_names = [
        ctx.unique_name("sim2real-dafm-zeta-"),
        ctx.unique_name("sim2real-dafm-alpha-"),
        ctx.unique_name("sim2real-dafm-mu-"),
        ctx.unique_name("sim2real-dafm-beta-"),
    ]
    for alarm_name in alarm_names:
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=100.0,
            ComparisonOperator="GreaterThanThreshold",
        )
        ctx.on_cleanup(lambda n=alarm_name: cw.delete_alarms(AlarmNames=[n]))

    def _order():
        alarms = cw.describe_alarms_for_metric(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions
        )["MetricAlarms"]
        return [a["AlarmName"] for a in alarms]

    first = _poll_until(_order, lambda names: set(names) == set(alarm_names), timeout_s=30, interval_s=2)
    second = _order()
    third = _order()

    assert second == first, f"order changed between repeated calls: {first} -> {second}"
    assert third == first, f"order changed between repeated calls: {first} -> {third}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
