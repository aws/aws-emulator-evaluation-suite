"""put-metric-data-visible-in-list-metrics."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-data-visible-in-list-metrics"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData implicitly creates the metric, which becomes visible via ListMetrics
    filtered by namespace/metric-name/dimension; metadata indexing can take minutes, so the
    poll is generous and its exhaustion fails."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "NewlyPublished"
    dim_value = ctx.unique_name("dim-")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Sim2RealDim", "Value": dim_value}],
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    def probe():
        return cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Sim2RealDim", "Value": dim_value}],
        )["Metrics"]

    left = ctx.time_left()
    deadline = time.monotonic() + (240.0 if left is None else min(240.0, left))
    metrics: list = []
    while time.monotonic() < deadline:
        metrics = probe()
        if metrics:
            break
        time.sleep(2)

    if not metrics:
        raise AssertionError("metric metadata did not appear in ListMetrics within the poll budget")

    assert metrics[0]["MetricName"] == metric_name, (
        f"expected MetricName {metric_name!r} in ListMetrics result, got {metrics[0]!r}"
    )
    assert {"Name": "Sim2RealDim", "Value": dim_value} in metrics[0]["Dimensions"], (
        f"expected dimension Sim2RealDim={dim_value!r} in {metrics[0]['Dimensions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
