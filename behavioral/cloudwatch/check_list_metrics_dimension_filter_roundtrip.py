"""list-metrics-dimension-filter-roundtrip."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-metrics-dimension-filter-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics with a Dimensions filter returns only the metric datapoint
    series matching that exact dimension value, not sibling series."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "RequestsByColor"
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Color", "Value": "blue"}],
                "Timestamp": now,
                "Value": 1.0,
            },
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Color", "Value": "green"}],
                "Timestamp": now,
                "Value": 1.0,
            },
        ],
    )

    def _blue_metrics():
        resp = cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Color", "Value": "blue"}],
        )
        return resp["Metrics"]

    metrics = _poll_until(_blue_metrics, lambda m: len(m) >= 1, timeout_s=120, interval_s=5)
    assert len(metrics) == 1, f"expected exactly one series for Color=blue, got {metrics}"
    dims = {d["Name"]: d["Value"] for d in metrics[0]["Dimensions"]}
    assert dims == {"Color": "blue"}, dims

    all_metrics = cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"]
    colors = {tuple(sorted((d["Name"], d["Value"]) for d in m["Dimensions"])) for m in all_metrics}
    assert colors == {(("Color", "blue"),), (("Color", "green"),)}, (
        f"expected the unfiltered listing to round-trip both series exactly, got {colors}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
