"""list-metrics-dimension-filter."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-metrics-dimension-filter"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics filters returned metrics by namespace and dimension value."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Requests"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": 1.0,
                "Dimensions": [{"Name": "Service", "Value": "checkout"}],
            },
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": 1.0,
                "Dimensions": [{"Name": "Service", "Value": "billing"}],
            },
        ],
    )

    def probe():
        return cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Service", "Value": "checkout"}],
        )

    try:
        resp = _poll_until(
            probe,
            lambda r: len(r.get("Metrics", [])) > 0,
            timeout_s=240,
            interval_s=3,
            description="freshly-published custom metric to be indexed by ListMetrics",
        )
    except AssertionError as exc:
        # ListMetrics indexing is eventually consistent (documented up to ~15 min); this check's
        # window is much shorter, so a timeout here is a genuine fail.
        raise AssertionError(f"ListMetrics did not index the custom metric in time: {exc}") from exc
    metrics = resp["Metrics"]
    assert len(metrics) == 1, f"expected exactly the checkout-dimensioned metric, got {metrics}"
    dims = {d["Name"]: d["Value"] for d in metrics[0]["Dimensions"]}
    assert dims == {"Service": "checkout"}, f"unexpected dimensions: {dims}"

    def probe_billing():
        return cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": "Service", "Value": "billing"}],
        )

    resp_billing = _poll_until(
        probe_billing,
        lambda r: len(r.get("Metrics", [])) > 0,
        timeout_s=60,
        interval_s=3,
        description="billing-dimensioned metric (published alongside checkout) to be indexed",
    )
    billing_metrics = resp_billing["Metrics"]
    assert len(billing_metrics) == 1, f"expected exactly the billing-dimensioned metric, got {billing_metrics}"
    billing_dims = {d["Name"]: d["Value"] for d in billing_metrics[0]["Dimensions"]}
    assert billing_dims == {"Service": "billing"}, f"unexpected dimensions: {billing_dims}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
