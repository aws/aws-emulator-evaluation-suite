"""put-metric-data-namespace-isolation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-namespace-isolation"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same MetricName published under two different namespaces stays fully
    isolated: GetMetricStatistics scoped to one namespace never picks up the
    other namespace's value."""
    cw = ctx.client("cloudwatch")
    namespace_a = ctx.unique_name("sim2real-behav-ns-a-")
    namespace_b = ctx.unique_name("sim2real-behav-ns-b-")
    metric_name = "SharedMetricName"
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace_a,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 11.0}],
    )
    cw.put_metric_data(
        Namespace=namespace_b,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 22.0}],
    )

    def _sum(namespace: str):
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum"],
        )
        return resp["Datapoints"]

    dp_a = _poll_until(lambda: _sum(namespace_a), lambda dp: len(dp) >= 1, timeout_s=120, interval_s=5)
    dp_b = _poll_until(lambda: _sum(namespace_b), lambda dp: len(dp) >= 1, timeout_s=120, interval_s=5)

    assert len(dp_a) == 1, f"expected exactly 1 datapoint for namespace_a, got {dp_a!r}"
    assert dp_a[0]["Sum"] == 11.0, f"expected Sum=11.0 for namespace_a, got {dp_a[0]['Sum']!r}"
    assert len(dp_b) == 1, f"expected exactly 1 datapoint for namespace_b, got {dp_b!r}"
    assert dp_b[0]["Sum"] == 22.0, f"expected Sum=22.0 for namespace_b, got {dp_b[0]['Sum']!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
