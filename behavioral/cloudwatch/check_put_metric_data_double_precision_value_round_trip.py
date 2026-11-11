"""put-metric-data-double-precision-value-round-trip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-double-precision-value-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A high-precision floating point metric value survives PutMetricData ingestion and
    GetMetricStatistics retrieval without precision loss beyond double-precision (64-bit
    float) storage tolerance."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-")
    metric_name = ctx.unique_name("sim2real-behav-")
    value = 123456789.123456789  # more significant digits than a double can hold exactly
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": value,
                "Unit": "None",
            }
        ],
    )

    start = now - timedelta(minutes=5)
    end = now + timedelta(minutes=5)
    datapoint = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Maximum", "SampleCount"],
        )
        points = resp["Datapoints"]
        if points:
            datapoint = points[0]
            break
        time.sleep(5)
    if datapoint is None:
        raise AssertionError("metric datapoint never became available via GetMetricStatistics")

    assert datapoint["SampleCount"] == 1.0, (
        f"expected exactly 1 sample aggregated into the period, got {datapoint['SampleCount']!r}"
    )

    returned = datapoint["Maximum"]
    # float64 relative epsilon is ~2.22e-16; 1e-9 is generous enough to absorb any
    # decimal-string round-trip through the wire protocol while still failing hard on a
    # float32-level truncation (~1.2e-7 relative) that the previous 1e-6 tolerance let through.
    tolerance = 1e-9 * max(1.0, abs(value))
    assert abs(returned - value) < tolerance, (
        f"precision loss beyond tolerance: sent {value!r}, got {returned!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
