"""put-metric-data-base64-like-string-dimension-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-data-base64-like-string-dimension-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dimension value that looks like a base64-encoded blob, including trailing
    '=' padding characters, round-trips through ListMetrics unchanged -- the padding
    must not be stripped or the value otherwise re-encoded.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-b64-")
    metric_name = "Base64DimensionTest"
    dim_name = "Payload"
    dim_value = "U29tZURhdGFUb0VuY29kZTEyMzQ1Njc4OTA="

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": dim_name, "Value": dim_value}],
                "Value": 1.0,
            }
        ],
    )

    def _probe():
        return cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"]

    # ListMetrics catalog inclusion for a brand-new metric can lag (documented as up
    # to ~15 minutes on PutMetricData); poll generously for the metric to appear.
    found = _poll_until(_probe, lambda m: len(m) > 0, timeout_s=240.0, interval_s=10.0)
    assert len(found) == 1, found
    assert found[0]["Dimensions"] == [{"Name": dim_name, "Value": dim_value}], (
        f"dimension corrupted: expected [{{'Name': {dim_name!r}, 'Value': {dim_value!r}}}], "
        f"got {found[0]['Dimensions']!r}"
    )
    assert found[0]["Dimensions"][0]["Value"].endswith("="), "padding character was stripped"


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
