"""describe-alarms-for-metric-result-order-stable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-result-order-stable"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns the same alarm ordering across repeated,
    identical calls (no shuffling between calls)."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-dafm-")
    metric_name = "StableOrderMetric"
    dims = [{"Name": "Case", "Value": "stable"}]

    alarm_names = [ctx.unique_name(f"sim2real-cw-dafm-alarm-{i}-") for i in range(4)]
    for name in alarm_names:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=ns,
            MetricName=metric_name,
            Dimensions=dims,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    def _names():
        resp = cw.describe_alarms_for_metric(
            Namespace=ns, MetricName=metric_name, Dimensions=dims, Statistic="Average", Period=60
        )
        return [a["AlarmName"] for a in resp["MetricAlarms"]]

    # PutMetricAlarm -> DescribeAlarmsForMetric visibility is not guaranteed instantaneous,
    # so the first read is a bounded retry (not a sleep) waiting for all 4 alarms to appear
    # before the stability comparison begins; a slow-but-correct target must not be graded
    # as having shuffled the order.
    deadline = time.monotonic() + 30
    first = _names()
    while set(first) != set(alarm_names) and time.monotonic() < deadline:
        time.sleep(2)
        first = _names()
    assert set(first) == set(alarm_names), f"expected alarms {alarm_names}, got {first}"

    second = _names()
    third = _names()
    assert first == second == third, f"order changed across repeated calls: {first} / {second} / {third}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
