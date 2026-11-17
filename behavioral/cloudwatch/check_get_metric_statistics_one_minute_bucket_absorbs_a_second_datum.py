"""get-metric-statistics-one-minute-bucket-absorbs-a-second-datum."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-statistics-one-minute-bucket-absorbs-a-second-datum"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]


def _wait_for_datapoints(probe, is_ready, *, budget_s=120.0, interval_s=3.0, description="condition"):
    """Call probe() until is_ready(result) holds; raise naming the last observation otherwise."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = probe()
        if is_ready(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {budget_s}s; last observation {last!r}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """At Period=60, a single published datum reads back as one datapoint whose Sum, Average,
    Minimum and Maximum equal that value with SampleCount 1.0; a second datum landing in the
    same minute updates that datapoint instead of producing a second one."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-onebucket-")
    metric_name = "SoleReading"
    minute_start = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(second=0, microsecond=0)
    first_ts = minute_start + timedelta(seconds=12)
    second_ts = minute_start + timedelta(seconds=41)
    first_value = 18.0
    second_value = 46.0

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": first_ts, "Value": first_value, "Unit": "Count"},
        ],
    )

    def probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=minute_start,
            EndTime=minute_start + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum", "Average", "Minimum", "Maximum", "SampleCount"],
        )["Datapoints"]

    first_read = _wait_for_datapoints(
        probe,
        lambda dps: bool(dps) and dps[0].get("SampleCount") == 1.0,
        description="the lone datum became one datapoint with SampleCount 1.0",
    )
    assert len(first_read) == 1, f"expected exactly one datapoint, got {len(first_read)}: {first_read!r}"
    dp = first_read[0]
    assert dp["Sum"] == first_value, f"Sum: expected {first_value!r}, got {dp['Sum']!r}"
    assert dp["Average"] == first_value, f"Average: expected {first_value!r}, got {dp['Average']!r}"
    assert dp["Minimum"] == first_value, f"Minimum: expected {first_value!r}, got {dp['Minimum']!r}"
    assert dp["Maximum"] == first_value, f"Maximum: expected {first_value!r}, got {dp['Maximum']!r}"
    assert dp["SampleCount"] == 1.0, f"SampleCount: expected 1.0, got {dp['SampleCount']!r}"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Timestamp": second_ts, "Value": second_value, "Unit": "Count"},
        ],
    )

    second_read = _wait_for_datapoints(
        probe,
        lambda dps: bool(dps) and dps[0].get("SampleCount") == 2.0,
        description="the second datum in the same minute merged into the existing datapoint",
    )
    assert len(second_read) == 1, (
        f"a second datum in the same minute produced {len(second_read)} datapoints, expected "
        f"the existing one to absorb it: {second_read!r}"
    )
    dp2 = second_read[0]
    expected_sum = first_value + second_value
    assert dp2["Sum"] == expected_sum, f"Sum: expected {expected_sum!r}, got {dp2['Sum']!r}"
    assert dp2["Average"] == expected_sum / 2.0, (
        f"Average: expected {expected_sum / 2.0!r}, got {dp2['Average']!r}"
    )
    assert dp2["Minimum"] == min(first_value, second_value), (
        f"Minimum: expected {min(first_value, second_value)!r}, got {dp2['Minimum']!r}"
    )
    assert dp2["Maximum"] == max(first_value, second_value), (
        f"Maximum: expected {max(first_value, second_value)!r}, got {dp2['Maximum']!r}"
    )
    assert dp2["SampleCount"] == 2.0, f"SampleCount: expected 2.0, got {dp2['SampleCount']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
