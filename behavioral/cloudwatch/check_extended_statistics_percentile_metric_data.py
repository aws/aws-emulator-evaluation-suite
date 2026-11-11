"""extended-statistics-percentile-metric-data."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "extended-statistics-percentile-metric-data"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExtendedStatistics p0/p100 return the exact min/max of the published values, distinct from Average."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real-CW-")
    metric_name = "PercentileMetric"

    bucket_start = (datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=3))
    values = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": bucket_start, "Value": v} for v in values
        ],
    )

    stats = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=bucket_start,
            EndTime=bucket_start + timedelta(seconds=60),
            Period=60,
            Statistics=["SampleCount", "Average", "Minimum", "Maximum"],
            ExtendedStatistics=["p0", "p100"],
        )["Datapoints"],
        lambda dps: len(dps) == 1 and dps[0].get("SampleCount") == len(values),
        timeout_s=90.0,
    )
    if len(stats) != 1 or stats[0].get("SampleCount") != len(values):
        raise AssertionError(
            f"all {len(values)} published samples never aggregated into one datapoint within the "
            f"ingestion window; got datapoints={stats!r}"
        )

    dp = stats[0]
    assert dp["Minimum"] == 10.0, f"Minimum must equal the published minimum 10.0, got {dp['Minimum']}"
    assert dp["Maximum"] == 100.0, f"Maximum must equal the published maximum 100.0, got {dp['Maximum']}"
    assert dp["Average"] == 55.0, f"Average must equal the arithmetic mean 55.0, got {dp['Average']}"
    ext = dp["ExtendedStatistics"]
    assert ext["p0"] == 10.0, f"ExtendedStatistics p0 must equal the distribution minimum 10.0, got {ext['p0']}"
    assert ext["p100"] == 100.0, f"ExtendedStatistics p100 must equal the distribution maximum 100.0, got {ext['p100']}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
