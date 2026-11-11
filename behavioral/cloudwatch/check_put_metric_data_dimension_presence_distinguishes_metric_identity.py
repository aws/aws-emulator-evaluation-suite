"""put-metric-data-dimension-presence-distinguishes-metric-identity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-data-dimension-presence-distinguishes-metric-identity"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same MetricName published with one dimension and with none is two metric identities;
    ListMetrics lists exactly those two, never conflating them."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "DimensionPresenceTest"
    dim_name = "Stage"
    dim_value = "prod"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": dim_name, "Value": dim_value}],
                "Value": 1.0,
            },
            {"MetricName": metric_name, "Value": 2.0},
        ],
    )

    def _list():
        return cw.list_metrics(Namespace=namespace, MetricName=metric_name).get("Metrics", [])

    def _both_present(metrics):
        has_dim = any(
            m.get("Dimensions") == [{"Name": dim_name, "Value": dim_value}] for m in metrics
        )
        has_bare = any(m.get("Dimensions", []) == [] for m in metrics)
        return has_dim and has_bare

    metrics = _poll_until(_list, _both_present, timeout_s=180.0, interval_s=10.0)
    identity_keys = {
        tuple(sorted((d["Name"], d["Value"]) for d in m.get("Dimensions", []))) for m in metrics
    }
    expected_keys = {(), ((dim_name, dim_value),)}
    assert identity_keys == expected_keys, (
        f"expected identities {expected_keys!r} (dimensioned + bare, no conflation and no extras), "
        f"got {identity_keys!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
