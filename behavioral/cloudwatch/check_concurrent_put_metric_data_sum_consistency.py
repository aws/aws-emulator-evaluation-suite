"""concurrent-put-metric-data-sum-consistency."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "concurrent-put-metric-data-sum-consistency"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutMetricData calls against the same metric each individually succeed (no
    write is dropped/throttled away silently), and once ingested, the aggregated Sum/SampleCount
    for that minute equal exactly N -- no double counting or lost updates under contention."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "ConcurrentCounter"
    racer_count = 20

    def racer(i: int):
        try:
            cw.put_metric_data(
                Namespace=namespace,
                MetricData=[{"MetricName": metric_name, "Value": 1.0, "Unit": "Count"}],
            )
        except Exception as exc:  # noqa: BLE001 -- captured so one racer's failure doesn't abort the rest
            return i, exc
        return i, None

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(racer, i) for i in range(racer_count)]
        for future in as_completed(futures):
            results.append(future.result())

    failures = [(i, repr(exc)) for i, exc in results if exc is not None]
    assert not failures, (
        f"expected all {racer_count} concurrent PutMetricData calls to succeed, "
        f"{len(failures)} failed: {failures}"
    )

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=5)
    end = now + timedelta(minutes=5)

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    datapoints: list = []
    while time.monotonic() < deadline:
        datapoints = probe()
        if datapoints and sum(d["SampleCount"] for d in datapoints) >= racer_count:
            break
        time.sleep(2)

    total_count = sum(d["SampleCount"] for d in datapoints) if datapoints else 0
    if total_count < racer_count:
        raise AssertionError(
            f"only {total_count}/{racer_count} concurrent writes became queryable within budget"
        )

    total_sum = sum(d["Sum"] for d in datapoints)
    assert total_count == racer_count, (
        f"expected SampleCount total {racer_count} across all datapoints, got {total_count} "
        f"(higher means double counting, lower means a lost write)"
    )
    assert abs(total_sum - racer_count) < 1e-6, (
        f"expected Sum total {float(racer_count)} ({racer_count} writers x 1.0), got {total_sum}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
