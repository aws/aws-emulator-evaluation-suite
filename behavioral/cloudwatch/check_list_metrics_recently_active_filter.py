"""list-metrics-recently-active-filter."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-metrics-recently-active-filter"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics(RecentlyActive='PT3H') returns exactly the metric just published (its MetricName and
    Namespace), so the filter matches recent activity instead of never matching."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "RecentlyActiveMetric"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": datetime.now(timezone.utc),
                "Value": 3.0,
            }
        ],
    )

    metrics = _poll_for_metric(cw, namespace=namespace, metric_name=metric_name)
    if metrics is None:
        # ListMetrics indexes new metrics asynchronously and can lag by minutes, so the poll
        # allows up to 180 s before it fails.
        raise AssertionError("metric metadata did not land in ListMetrics within the poll window")

    assert len(metrics) == 1, metrics
    assert metrics[0]["MetricName"] == metric_name, (
        f"expected MetricName {metric_name!r}, got {metrics[0]['MetricName']!r}"
    )
    assert metrics[0]["Namespace"] == namespace, (
        f"expected Namespace {namespace!r}, got {metrics[0]['Namespace']!r}"
    )


def _poll_for_metric(cw, *, namespace, metric_name, timeout_s=180.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.list_metrics(Namespace=namespace, MetricName=metric_name, RecentlyActive="PT3H")
        if resp["Metrics"]:
            return resp["Metrics"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
