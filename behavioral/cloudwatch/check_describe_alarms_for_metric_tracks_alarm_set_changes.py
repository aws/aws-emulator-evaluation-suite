"""describe-alarms-for-metric-tracks-alarm-set-changes."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-tracks-alarm-set-changes"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric reflects the live set of alarms configured
    against a given metric/namespace/statistic as alarms are added and removed."""
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealMetricAlarmSet")
    metric_name = "RequestLatency"
    statistic = "Average"
    period = 60

    def _alarm_names_for_metric() -> set[str]:
        resp = cw.describe_alarms_for_metric(
            MetricName=metric_name, Namespace=namespace, Statistic=statistic, Period=period
        )
        return {a["AlarmName"] for a in resp.get("MetricAlarms", [])}

    # 0. Baseline: nothing configured against this brand-new namespace/metric yet.
    baseline = _alarm_names_for_metric()
    assert baseline == set(), f"expected no alarms yet, found {baseline}"

    alarm_a = ctx.unique_name("sim2real-metricalarm-a-")
    alarm_b = ctx.unique_name("sim2real-metricalarm-b-")

    def _put(alarm_name: str) -> None:
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            Statistic=statistic,
            Period=period,
            EvaluationPeriods=1,
            Threshold=100.0,
            ComparisonOperator="GreaterThanThreshold",
        )

    _put(alarm_a)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_a]) if _alarm_exists(cw, alarm_a) else None)

    # 1. After the first alarm, the set contains exactly it.
    after_a = _poll_until(
        _alarm_names_for_metric, lambda names: names == {alarm_a}, timeout_s=20, interval_s=2
    )
    assert after_a == {alarm_a}, f"expected only {alarm_a!r} after first put, got {after_a}"

    _put(alarm_b)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_b]) if _alarm_exists(cw, alarm_b) else None)

    # 2. After the second alarm, the set contains both.
    after_b = _poll_until(
        _alarm_names_for_metric,
        lambda names: names == {alarm_a, alarm_b},
        timeout_s=20,
        interval_s=2,
    )
    assert after_b == {alarm_a, alarm_b}, f"expected both alarms after second put, got {after_b}"

    # 3. Deleting one alarm removes only it from the set.
    cw.delete_alarms(AlarmNames=[alarm_a])
    after_delete_a = _poll_until(
        _alarm_names_for_metric, lambda names: names == {alarm_b}, timeout_s=20, interval_s=2
    )
    assert after_delete_a == {alarm_b}, f"expected only {alarm_b!r} to remain after deleting {alarm_a!r}, got {after_delete_a}"

    # 4. Deleting the last alarm empties the set.
    cw.delete_alarms(AlarmNames=[alarm_b])
    after_delete_b = _poll_until(
        _alarm_names_for_metric, lambda names: names == set(), timeout_s=20, interval_s=2
    )
    assert after_delete_b == set(), f"expected no alarms after deleting {alarm_b!r} too, got {after_delete_b}"


def _alarm_exists(cw: Any, alarm_name: str) -> bool:
    resp = cw.describe_alarms(AlarmNames=[alarm_name])
    return bool(resp.get("MetricAlarms"))


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
