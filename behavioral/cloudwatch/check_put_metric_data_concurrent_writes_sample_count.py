"""put-metric-data-concurrent-writes-sample-count."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-concurrent-writes-sample-count"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]

_WRITERS = 20


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutMetricData callers, each publishing a single Value=1
    datapoint for the same metric/timestamp bucket, are all durably aggregated:
    SampleCount and Sum both equal N with no writes lost under contention."""
    cw = ctx.client("cloudwatch")
    # No ctx.on_cleanup: CloudWatch has no DeleteMetric/DeleteNamespace API, so this
    # namespace is a permanent (uniquified) mark on the account, not an unregistered leak.
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "ConcurrentHits"
    dim = {"Name": "Shard", "Value": "0"}
    now = datetime.now(timezone.utc)

    def _write(i: int) -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Dimensions": [dim],
                    "Timestamp": now,
                    "Value": 1.0,
                    "Unit": "Count",
                }
            ],
        )

    with ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        list(pool.map(_write, range(_WRITERS)))

    def _stats():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[dim],
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount", "Average", "Minimum", "Maximum"],
        )
        return resp["Datapoints"]

    datapoints = _poll_until(
        _stats, lambda dp: len(dp) >= 1 and dp[0]["SampleCount"] >= float(_WRITERS), timeout_s=120, interval_s=5
    )
    assert len(datapoints) == 1, datapoints
    dp = datapoints[0]
    assert dp["SampleCount"] == float(_WRITERS), (
        f"expected SampleCount {_WRITERS} from {_WRITERS} concurrent writers, got {dp['SampleCount']}"
    )
    assert dp["Sum"] == float(_WRITERS), f"expected Sum {_WRITERS}, got {dp['Sum']}"
    # Every writer publishes the identical Value=1.0, so the merged extremes and the
    # mean are pinned regardless of arrival order -- not a guessed derivation.
    assert dp["Average"] == 1.0, f"expected Average 1.0 (Sum/SampleCount), got {dp['Average']}"
    assert dp["Minimum"] == 1.0 and dp["Maximum"] == 1.0, (
        f"every writer published Value=1.0, expected Minimum=Maximum=1.0, "
        f"got Minimum={dp['Minimum']} Maximum={dp['Maximum']}"
    )


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
