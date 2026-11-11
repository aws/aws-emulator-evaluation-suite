"""list-metrics-after-put-metric-data."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-metrics-after-put-metric-data"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics discovers a freshly published custom metric with its exact dimension set."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealListMetrics")
    metric_name = "DiscoverableMetric"
    dim_value = ctx.unique_name("host-")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "HostId", "Value": dim_value}],
                "Value": 1.0,
            }
        ],
    )

    metrics = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"],
        lambda ms: len(ms) > 0,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"ListMetrics({namespace}, {metric_name}) surfacing the published metric",
    )
    assert len(metrics) == 1, f"expected exactly 1 metric, got {metrics}"
    metric = metrics[0]
    assert metric["Namespace"] == namespace, f"expected namespace {namespace!r}, got {metric['Namespace']!r}"
    assert metric["MetricName"] == metric_name, f"expected metric name {metric_name!r}, got {metric['MetricName']!r}"
    assert metric["Dimensions"] == [{"Name": "HostId", "Value": dim_value}], metric["Dimensions"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
