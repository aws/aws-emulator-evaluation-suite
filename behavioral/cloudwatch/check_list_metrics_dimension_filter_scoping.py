"""list-metrics-dimension-filter-scoping."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-metrics-dimension-filter-scoping"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics with a Dimensions filter returns only metrics carrying that exact dimension
    name/value pair, scoping out sibling metrics published under the same namespace/metric name
    with a different dimension value."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    metric_name = "DimScopedMetric"
    blue = ctx.unique_name("blue-")
    green = ctx.unique_name("green-")

    for value in (blue, green):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Dimensions": [{"Name": "Env", "Value": value}],
                    "Value": 1.0,
                }
            ],
        )

    def probe():
        return cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Env", "Value": blue}],
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

    for metric in metrics:
        dims = {d["Name"]: d["Value"] for d in metric["Dimensions"]}
        assert dims.get("Env") == blue, dims
        assert dims.get("Env") != green, f"expected Env={blue!r}, sibling value {green!r} leaked into scoped results: {dims}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
