"""concurrent-put-metric-data-aggregation-no-lost-writes."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "concurrent-put-metric-data-aggregation-no-lost-writes"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutMetricData callers each writing a single datapoint into the same
    metric/timestamp bucket must all be aggregated: no writes silently dropped under
    contention (SampleCount == N, Sum == N)."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric = "ConcurrentMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    n = 10

    def put_one(_i):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric, "Timestamp": now, "Value": 1.0, "Unit": "Count"}],
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(put_one, range(n)))

    def probe():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(
        probe,
        lambda dp: len(dp) > 0 and float(dp[0].get("SampleCount", 0.0)) >= n,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"all {n} concurrent writes merged into one queryable datapoint",
    )

    dp = datapoints[0]
    assert int(dp["SampleCount"]) == n, f"expected SampleCount={n} from {n} concurrent writers, got {dp['SampleCount']}"
    assert abs(dp["Sum"] - n) < 1e-6, f"expected Sum={n}, got {dp['Sum']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
