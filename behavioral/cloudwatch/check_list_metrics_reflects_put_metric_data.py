"""list-metrics-reflects-put-metric-data."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-metrics-reflects-put-metric-data"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After PutMetricData, ListMetrics eventually surfaces the new metric with its exact
    namespace, name, and dimensions (metric metadata catalog stays in sync with the data
    plane)."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric = "ListedMetric"
    dim_value = ctx.unique_name("host-")
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Dimensions": [{"Name": "Host", "Value": dim_value}],
                "Timestamp": now,
                "Value": 1.0,
            }
        ],
    )

    def probe():
        return cw.list_metrics(Namespace=namespace, MetricName=metric)["Metrics"]

    metrics = _poll_until(
        probe,
        lambda m: len(m) > 0,
        timeout_s=200.0,
        interval_s=10.0,
        description="metric metadata surfaced in ListMetrics",
    )

    assert len(metrics) == 1, f"expected exactly 1 metric for {namespace}/{metric}, got {metrics}"
    found = metrics[0]
    assert found["Namespace"] == namespace, f"expected Namespace={namespace!r}, got {found['Namespace']!r}"
    assert found["MetricName"] == metric, f"expected MetricName={metric!r}, got {found['MetricName']!r}"
    assert found["Dimensions"] == [{"Name": "Host", "Value": dim_value}], (
        f"expected Dimensions=[Host={dim_value!r}], got {found['Dimensions']}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
