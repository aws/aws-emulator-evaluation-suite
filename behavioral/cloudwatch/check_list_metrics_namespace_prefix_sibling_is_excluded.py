"""list-metrics-namespace-prefix-sibling-is-excluded."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-metrics-namespace-prefix-sibling-is-excluded"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


def _poll_until(probe, predicate, *, timeout_s=240.0, interval_s=3.0, description="condition"):
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
    """ListMetrics(Namespace=N) lists exactly the metrics published to N, never a metric
    published to a sibling namespace that merely shares N as a string prefix, and a MetricName
    filter scoped to N excludes a metric that only exists under the sibling namespace."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    namespace_sibling = namespace + "-x"

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "RequestCount", "Value": 42.0, "Unit": "Count"},
            {"MetricName": "Latency", "Value": 125.5, "Unit": "Milliseconds"},
        ],
    )
    cw.put_metric_data(
        Namespace=namespace_sibling,
        MetricData=[{"MetricName": "Other", "Value": 1.0, "Unit": "Count"}],
    )

    def probe_sibling():
        return cw.list_metrics(Namespace=namespace_sibling).get("Metrics", [])

    sibling_metrics = _poll_until(
        probe_sibling,
        lambda ms: len(ms) > 0,
        description=f"ListMetrics(Namespace={namespace_sibling!r}) surfacing 'Other'",
    )
    sibling_names = {m["MetricName"] for m in sibling_metrics}
    assert sibling_names == {"Other"}, (
        f"expected ListMetrics(Namespace={namespace_sibling!r}) to list exactly ['Other'], "
        f"got {sorted(sibling_names)}"
    )

    def probe_namespace():
        return cw.list_metrics(Namespace=namespace).get("Metrics", [])

    namespace_metrics = _poll_until(
        probe_namespace,
        lambda ms: {m["MetricName"] for m in ms} == {"RequestCount", "Latency"},
        description=f"ListMetrics(Namespace={namespace!r}) surfacing both published metrics",
    )
    assert len(namespace_metrics) == 2, (
        f"expected ListMetrics(Namespace={namespace!r}) to list exactly 2 metrics, "
        f"got {namespace_metrics!r}"
    )
    for metric in namespace_metrics:
        assert metric["Namespace"] == namespace, (
            f"metric {metric['MetricName']!r} under ListMetrics(Namespace={namespace!r}) "
            f"carried Namespace {metric['Namespace']!r}, expected {namespace!r}"
        )
        assert metric.get("Dimensions", []) == [], (
            f"metric {metric['MetricName']!r} under ListMetrics(Namespace={namespace!r}) "
            f"carried Dimensions {metric.get('Dimensions')!r}, expected []"
        )

    scoped = cw.list_metrics(Namespace=namespace, MetricName="Other").get("Metrics", [])
    assert scoped == [], (
        f"ListMetrics(Namespace={namespace!r}, MetricName='Other') returned {scoped!r}, "
        f"expected an empty list: 'Other' only exists under the sibling namespace "
        f"{namespace_sibling!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
