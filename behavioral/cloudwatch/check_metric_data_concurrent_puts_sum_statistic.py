"""metric-data-concurrent-puts-sum-statistic."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-concurrent-puts-sum-statistic"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]

_RACERS = 10


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutMetricData calls for the same metric/timestamp must all be
    durably aggregated -- SampleCount and Sum must reflect exactly N points, none
    lost or double-counted under contention."""
    cw = ctx.client("cloudwatch")
    # No ctx.on_cleanup: CloudWatch has no DeleteMetric/DeleteNamespace API, so the
    # uniquified namespace this check creates cannot be removed and is a permanent,
    # metadata-only mark on the account rather than an unasserted leak.
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "ConcurrentValue"
    ts = datetime.now(timezone.utc).replace(microsecond=0)

    def _put(_i: int):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": 1.0, "Unit": "Count"}],
        )

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_put, i) for i in range(_RACERS)]
        for fut in as_completed(futures):
            fut.result()  # propagate any put_metric_data failure immediately

    dp = _poll_for_sample_count(ctx, namespace, metric_name, ts, expected=_RACERS)
    if dp is None:
        raise AssertionError(
            f"metric never reached SampleCount={_RACERS} within timeout (ingestion latency)",
        )

    assert dp["SampleCount"] == float(_RACERS), f"expected SampleCount={_RACERS}, got {dp['SampleCount']}"
    assert dp["Sum"] == float(_RACERS), f"expected Sum={_RACERS} (lost/duplicated writes under contention), got {dp['Sum']}"


def _poll_for_sample_count(ctx, namespace: str, metric_name: str, ts, expected: int, timeout_s: float = 150.0, interval_s: float = 5.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "SampleCount"],
        )
        if resp["Datapoints"] and resp["Datapoints"][0]["SampleCount"] >= expected:
            return resp["Datapoints"][0]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
