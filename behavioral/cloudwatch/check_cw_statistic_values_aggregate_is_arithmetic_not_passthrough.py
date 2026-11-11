"""cw-statistic-values-aggregate-is-arithmetic-not-passthrough."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cw-statistic-values-aggregate-is-arithmetic-not-passthrough"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two StatisticValues summaries in the same period are MERGED server-side, not passed through.

    The merged Average is 160/10 == 16.0, derivable only from the merged Sum and SampleCount."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthStatSetNs")
    metric = "MergedStatisticSet"
    t = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    first = {"SampleCount": 4.0, "Sum": 100.0, "Minimum": 10.0, "Maximum": 40.0}
    second = {"SampleCount": 6.0, "Sum": 60.0, "Minimum": 1.0, "Maximum": 50.0}

    for summary in (first, second):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": t,
                    "StatisticValues": summary,
                    "Unit": "Count",
                }
            ],
        )

    expected_count = first["SampleCount"] + second["SampleCount"]
    expected_sum = first["Sum"] + second["Sum"]
    expected_min = min(first["Minimum"], second["Minimum"])
    expected_max = max(first["Maximum"], second["Maximum"])
    expected_avg = expected_sum / expected_count

    def _probe() -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=t,
            EndTime=t + timedelta(seconds=60),
            Period=60,
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum", "Average"],
        )["Datapoints"]

    datapoints = _poll_until(
        _probe,
        lambda dps: len(dps) > 0 and float(dps[0].get("SampleCount", 0.0)) >= expected_count,
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"both StatisticValues summaries merged into one {t.isoformat()} bucket with "
            f"SampleCount {expected_count}"
        ),
    )
    assert len(datapoints) == 1, (
        f"two StatisticValues at the same timestamp produced {len(datapoints)!r} period buckets, "
        f"expected exactly 1: {datapoints!r}"
    )
    dp = datapoints[0]

    assert dp["SampleCount"] == expected_count, (
        f"merged SampleCount is {dp['SampleCount']!r}, expected {expected_count!r} "
        f"(4 + 6) -- the second summary replaced rather than merged"
    )
    assert dp["Sum"] == expected_sum, (
        f"merged Sum is {dp['Sum']!r}, expected {expected_sum!r} (100 + 60)"
    )
    assert dp["Minimum"] == expected_min, (
        f"merged Minimum is {dp['Minimum']!r}, expected {expected_min!r} -- the extreme must be "
        f"taken across BOTH summaries, and 1.0 is only present in the second"
    )
    assert dp["Maximum"] == expected_max, (
        f"merged Maximum is {dp['Maximum']!r}, expected {expected_max!r} -- 50.0 is only present "
        f"in the second summary"
    )
    assert abs(dp["Average"] - expected_avg) < 1e-9, (
        f"merged Average is {dp['Average']!r}, expected {expected_avg!r} == Sum/SampleCount == "
        f"{expected_sum}/{expected_count}; averaging the two submitted averages would give 17.5"
    )
    assert dp["Unit"] == "Count", f"the merged datapoint reports Unit {dp['Unit']!r}, expected 'Count'"


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
