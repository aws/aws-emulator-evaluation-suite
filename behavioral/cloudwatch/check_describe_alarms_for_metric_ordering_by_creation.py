"""describe-alarms-for-metric-ordering-by-creation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-ordering-by-creation"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric returns the alarms watching a given metric in a stable order
    across repeated calls when the underlying alarm set is unchanged."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-dafm-ns-")
    metric_name = "SharedMetric"
    # Deliberately non-alphabetical creation order.
    alarm_names = [
        ctx.unique_name("sim2real-alarm-zzz-"),
        ctx.unique_name("sim2real-alarm-aaa-"),
        ctx.unique_name("sim2real-alarm-mmm-"),
        ctx.unique_name("sim2real-alarm-bbb-"),
    ]
    for name in alarm_names:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric_name,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=100.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    def _order() -> list[str]:
        resp = cw.describe_alarms_for_metric(Namespace=namespace, MetricName=metric_name)
        return [a["AlarmName"] for a in resp["MetricAlarms"]]

    first = _order()
    assert sorted(first) == sorted(alarm_names), (
        f"DescribeAlarmsForMetric did not return exactly our {len(alarm_names)} alarms: {first}"
    )

    # Space the repeats out (not back-to-back) so a passing target has demonstrated
    # stability over wall-clock time, not just within one caching window.
    for _ in range(3):
        time.sleep(2)
        again = _order()
        assert again == first, f"alarm order changed across repeated calls: {first} vs {again}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
