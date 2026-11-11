"""concurrent-put-metric-data-aggregation."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

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

CHECK = "concurrent-put-metric-data-aggregation"
GROUP = 'concurrency'
SERVICES = ['cloudwatch']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutMetricData calls of value 1 into one period all succeed and aggregate into one
    datapoint with SampleCount and Sum equal to the number of calls: no update is lost."""
    cw = ctx.client("cloudwatch")
    # CloudWatch has no DeleteMetric, so the unique namespace stays behind.
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Concurrent"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    n_racers = 8

    def put_one(i):
        return cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 1.0, "Unit": "Count"}],
        )

    # Fire N PutMetricData calls at once; count how many succeeded.
    fns = [lambda i=i: put_one(i) for i in range(n_racers)]
    results: list = [None] * n_racers
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_racers) as ex:
        futs = {ex.submit(fn): idx for idx, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(futs):
            idx = futs[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for distribution assertions
                results[idx] = exc
    successes = sum(1 for r in results if not isinstance(r, BaseException))
    assert successes == n_racers, f"expected all {n_racers} PutMetricData calls to succeed, got {successes}"

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["SampleCount", "Sum"],
        )

    resp = _poll_until(probe, lambda r: len(r.get("Datapoints", [])) > 0, timeout_s=30, interval_s=2)
    datapoints = resp["Datapoints"]
    assert len(datapoints) == 1, (
        f"{n_racers} writes at the identical timestamp landed in {len(datapoints)} period buckets, "
        f"expected exactly 1 (the merge under test): {datapoints!r}"
    )
    dp = datapoints[0]
    assert dp["SampleCount"] == float(n_racers), (
        f"expected SampleCount={n_racers} with no lost updates, got {dp['SampleCount']}"
    )
    assert dp["Sum"] == float(n_racers), f"expected Sum={n_racers}, got {dp['Sum']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
