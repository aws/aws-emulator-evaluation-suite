"""concurrent-put-metric-data-sum-aggregation."""
from __future__ import annotations

import datetime as dt
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-metric-data-sum-aggregation"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]

_RACERS = 10


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutMetricData calls for the same minute all land: Sum == N, SampleCount == N."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "ConcurrentMetric"
    ts = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)

    def _put(_i):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": 1.0, "Unit": "Count"}],
        )

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        list(pool.map(_put, range(_RACERS)))

    datapoints = _poll_for_datapoints(cw, namespace, metric_name, ts)
    if datapoints is None:
        raise AssertionError("aggregated metric datapoint did not land within the ingestion poll window")
    assert len(datapoints) == 1, (
        f"{_RACERS} writes at the identical, truncated-to-the-minute timestamp produced "
        f"{len(datapoints)} period buckets, expected exactly 1: {datapoints!r}"
    )
    datapoint = datapoints[0]

    assert datapoint["Sum"] == float(_RACERS), (
        f"expected Sum == {_RACERS} across {_RACERS} concurrent writers, got {datapoint['Sum']}"
    )
    assert datapoint["SampleCount"] == float(_RACERS), (
        f"expected SampleCount == {_RACERS}, got {datapoint['SampleCount']}"
    )


def _poll_for_datapoints(cw, namespace, metric_name, ts, *, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=ts - dt.timedelta(minutes=1),
            EndTime=ts + dt.timedelta(minutes=2),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )
        if resp["Datapoints"]:
            return resp["Datapoints"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
