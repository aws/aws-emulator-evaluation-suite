"""cw-concurrent-put-metric-data-same-timestamp-sum-is-exact."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cw-concurrent-put-metric-data-same-timestamp-sum-is-exact"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]

_RACERS = 12


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Twelve simultaneous PutMetricData writes for one timestamp merge with no loss or duplication.

    SampleCount and Sum are exactly the accepted writes' count and total, all in ONE period bucket."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthRaceNs")
    metric = "ContendedMetric"
    # One frozen timestamp for every racer: the merge is what is being graded, so they must all
    # target the same period bucket.
    t = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _racer(i: int) -> tuple[int, int | None, str | None]:
        try:
            resp = cw.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {"MetricName": metric, "Timestamp": t, "Value": 1.0, "Unit": "Count"}
                ],
            )
        except ClientError as exc:
            return i, None, f"{exc.response.get('Error', {}).get('Code')}: {exc}"
        return i, resp["ResponseMetadata"]["HTTPStatusCode"], None

    results = []
    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_racer, i) for i in range(_RACERS)]
        for fut in as_completed(futures):
            results.append(fut.result())

    ok = [r for r in results if r[1] == 200]
    errors = [(r[0], r[2]) for r in results if r[1] != 200]
    assert len(ok) == _RACERS, (
        f"only {len(ok)!r}/{_RACERS} concurrent writes were accepted; the rejections were "
        f"{errors!r}. The aggregation invariant below is only meaningful over accepted writes"
    )

    def _probe() -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=t,
            EndTime=t + timedelta(seconds=60),
            Period=60,
            Statistics=["Sum", "SampleCount", "Average", "Minimum", "Maximum"],
        )["Datapoints"]

    datapoints = _poll_until(
        _probe,
        lambda dps: len(dps) > 0 and float(dps[0].get("SampleCount", 0.0)) >= float(_RACERS),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"all {_RACERS} concurrent writes became visible as one merged datapoint",
    )
    assert len(datapoints) == 1, (
        f"{_RACERS} writes at the identical timestamp produced {len(datapoints)!r} period buckets, "
        f"expected exactly 1: {datapoints!r}"
    )
    dp = datapoints[0]
    assert dp["SampleCount"] == float(_RACERS), (
        f"SampleCount is {dp['SampleCount']!r} for {_RACERS} accepted concurrent writes -- a lower "
        f"figure is a lost write, a higher one is a double count"
    )
    assert dp["Sum"] == float(_RACERS), (
        f"Sum is {dp['Sum']!r}, expected {float(_RACERS)!r} ({_RACERS} x 1.0)"
    )
    assert abs(dp["Average"] - 1.0) < 1e-9, (
        f"Average is {dp['Average']!r}, expected 1.0 == Sum/SampleCount"
    )
    assert dp["Minimum"] == 1.0 and dp["Maximum"] == 1.0, (
        f"every racer wrote exactly 1.0, so the merged extremes must both be 1.0, got "
        f"Minimum={dp['Minimum']!r} Maximum={dp['Maximum']!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion.

    Deliberately raises rather than returning the last value: 'the datapoint never came back' is
    the only interesting failure on a metric-read surface.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
