"""put-metric-data-high-precision-float-value-round-trip."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-high-precision-float-value-round-trip"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single metric datum with a value carrying many significant decimal digits
    comes back from GetMetricStatistics as an Average that matches the published
    value to within float64 fidelity -- no truncation to a coarser decimal grid.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-precision-")
    metric_name = "HighPrecisionValue"
    value = 123456.789012345
    ts = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Value": value,
                "Timestamp": ts,
                "Unit": "None",
            }
        ],
    )

    def _probe():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
            Period=300,
            Statistics=["Average", "SampleCount"],
        )["Datapoints"]

    datapoints = _poll_until(_probe, lambda d: len(d) > 0, timeout_s=120.0, interval_s=5.0)
    assert len(datapoints) == 1, datapoints
    dp = datapoints[0]
    assert dp["SampleCount"] == 1.0, f"expected SampleCount 1.0, got {dp['SampleCount']!r}"
    assert math.isclose(dp["Average"], value, rel_tol=1e-9), (
        f"expected Average ~= {value!r}, got {dp['Average']!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
