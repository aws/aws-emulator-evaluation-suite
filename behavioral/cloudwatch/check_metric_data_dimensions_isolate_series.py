"""metric-data-dimensions-isolate-series."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-dimensions-isolate-series"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two datapoints published under the same namespace/metric name but different
    dimension values form independent time series -- querying by one dimension set
    must not be polluted by the other's value."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "DimensionedValue"
    ts = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Dimensions": [{"Name": "Series", "Value": "A"}], "Timestamp": ts, "Value": 10.0},
        ],
    )
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_name, "Dimensions": [{"Name": "Series", "Value": "B"}], "Timestamp": ts, "Value": 1000.0},
        ],
    )

    sum_a = _poll_series_sum(ctx, namespace, metric_name, "A", ts)
    sum_b = _poll_series_sum(ctx, namespace, metric_name, "B", ts)
    if sum_a is None or sum_b is None:
        raise AssertionError(
            "dimensioned metric data never became queryable within timeout",
        )

    assert sum_a == 10.0, f"series A polluted by series B, got Sum={sum_a}"
    assert sum_b == 1000.0, f"series B polluted by series A, got Sum={sum_b}"


def _poll_series_sum(ctx, namespace: str, metric_name: str, series: str, ts, timeout_s: float = 120.0, interval_s: float = 5.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Series", "Value": series}],
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum"],
        )
        if resp["Datapoints"]:
            return resp["Datapoints"][0]["Sum"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
