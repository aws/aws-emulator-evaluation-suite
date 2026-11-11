"""metric-data-sum-statistic-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "metric-data-sum-statistic-round-trip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData datapoints aggregate correctly: pushing five known values for the
    same metric/period and reading them back via GetMetricStatistics yields the exact
    Sum, SampleCount, Minimum, and Maximum."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/SumRoundTrip-")
    metric_name = "SumRoundTripMetric"
    # Anchor all datapoints to the same 60s period so they aggregate into one datapoint.
    period_start = int(time.time() // 60) * 60
    ts = period_start + 5
    values = [1.0, 2.0, 3.0, 4.0, 5.0]

    for v in values:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": v, "Timestamp": ts}],
        )

    datapoints = _poll_datapoints(cw, namespace, metric_name, period_start, timeout_s=150.0)
    assert datapoints, "aggregated datapoint never became visible"
    dp = datapoints[0]
    assert dp["SampleCount"] == float(len(values)), (
        f"expected SampleCount={float(len(values))}, got {dp['SampleCount']}"
    )
    assert dp["Sum"] == sum(values), f"expected Sum={sum(values)}, got {dp['Sum']}"
    assert dp["Minimum"] == min(values), f"expected Minimum={min(values)}, got {dp['Minimum']}"
    assert dp["Maximum"] == max(values), f"expected Maximum={max(values)}, got {dp['Maximum']}"


def _poll_datapoints(cw, namespace, metric_name, period_start, timeout_s, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        points = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=period_start - 60,
            EndTime=period_start + 120,
            Period=60,
            Statistics=["SampleCount", "Sum", "Minimum", "Maximum"],
        )["Datapoints"]
        if points:
            return points
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
