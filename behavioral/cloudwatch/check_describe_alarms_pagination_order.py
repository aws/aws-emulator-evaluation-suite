"""describe-alarms-pagination-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-pagination-order"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

_NAMESPACE = "SimParityProbe/Behavioral"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarms and DescribeAlarmsForMetric return alarms in a
    consistent, deterministic order across paginated requests."""
    cw = ctx.client("cloudwatch")
    prefix = ctx.unique_name("sim2real-behav-cwprobe-alarm-page-")
    metric_name = "SharedPagingMetric"
    n = 6
    # Create out of numeric order to make sure any observed ordering isn't
    # merely creation/insertion order.
    creation_order = [3, 0, 5, 1, 4, 2]
    names = [f"{prefix}-{i}" for i in range(n)]
    for i in creation_order:
        alarm_name = names[i]
        ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=_NAMESPACE,
            MetricName=metric_name,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=100.0 + i,
            ComparisonOperator="GreaterThanThreshold",
        )

    def probe_all_visible():
        resp = cw.describe_alarms(AlarmNamePrefix=prefix, MaxRecords=100)
        return resp.get("MetricAlarms", [])

    _poll_until(
        probe_all_visible, lambda alarms: len(alarms) == n, timeout_s=30, interval_s=2,
        description="all created alarms visible via DescribeAlarms",
    )

    paginated_names: list[str] = []
    next_token = None
    for _ in range(n + 2):  # bounded loop; n pages of size 2 plus slack
        kwargs = dict(AlarmNamePrefix=prefix, MaxRecords=2)
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cw.describe_alarms(**kwargs)
        paginated_names.extend(a["AlarmName"] for a in resp.get("MetricAlarms", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert len(paginated_names) == n, f"expected {n} alarms across pages, got {paginated_names}"
    assert len(set(paginated_names)) == n, f"paginated traversal must not duplicate alarms: {paginated_names}"

    full_resp = cw.describe_alarms(AlarmNamePrefix=prefix, MaxRecords=100)
    full_names = [a["AlarmName"] for a in full_resp.get("MetricAlarms", [])]

    assert paginated_names == full_names, (
        f"paginated order must match the single-call order; paginated={paginated_names} full={full_names}"
    )
    assert full_names == sorted(full_names), (
        f"DescribeAlarms results should be returned in a deterministic (alphabetical) order, got {full_names}"
    )

    # DescribeAlarmsForMetric: same underlying metric, no pagination support --
    # its ordering guarantee is that repeat calls with the same filter are
    # identical, and it surfaces every alarm watching that metric.
    resp1 = cw.describe_alarms_for_metric(Namespace=_NAMESPACE, MetricName=metric_name)
    resp2 = cw.describe_alarms_for_metric(Namespace=_NAMESPACE, MetricName=metric_name)
    names1 = [a["AlarmName"] for a in resp1.get("MetricAlarms", [])]
    names2 = [a["AlarmName"] for a in resp2.get("MetricAlarms", [])]
    assert names1 == names2, (
        f"DescribeAlarmsForMetric must return a deterministic order across repeat calls; "
        f"first={names1} second={names2}"
    )
    matching = {nm for nm in names1 if nm.startswith(prefix)}
    assert matching == set(names), (
        f"expected all {n} alarms watching {metric_name} to appear, got {names1}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
