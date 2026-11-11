"""op-contract-listMetrics-namespace-pattern."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-listMetrics-namespace-pattern"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics finds a published metric by Namespace and MetricName (with its Dimensions), an unrelated
    MetricName matches nothing, and a Namespace starting with ':' (outside the documented '[^:].*'
    pattern) is accepted by PutMetricData and listed under that namespace."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CWListDup")
    metric_name = ctx.unique_name("cw-listdup-metric-")
    dim_value = ctx.unique_name("dim-")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Probe", "Value": dim_value}],
                "Value": 7.0,
                "Unit": "Count",
            }
        ],
    )

    # success-path contract: the metric shows up, eventually, filtered by namespace+name
    found = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName=metric_name)["Metrics"],
        lambda metrics: len(metrics) == 1,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert len(found) == 1, f"metric never appeared in ListMetrics, last={found}"
    assert found[0]["Namespace"] == namespace, f"expected Namespace={namespace!r}, got {found[0]['Namespace']!r}"
    assert found[0]["MetricName"] == metric_name, f"expected MetricName={metric_name!r}, got {found[0]['MetricName']!r}"
    assert found[0]["Dimensions"] == [{"Name": "Probe", "Value": dim_value}], (
        f"expected Dimensions=[{{'Name': 'Probe', 'Value': {dim_value!r}}}], got {found[0]['Dimensions']!r}"
    )

    # an unrelated MetricName filter under the same namespace must never match it
    other_name = ctx.unique_name("cw-listdup-other-")
    mismatched = cw.list_metrics(Namespace=namespace, MetricName=other_name)["Metrics"]
    assert mismatched == [], f"unrelated MetricName unexpectedly matched: {mismatched}"

    # The model gives the Namespace pattern '[^:].*', but PutMetricData does not enforce it:
    # a ':'-prefixed namespace is accepted and listed like any other.
    colon_namespace = ":" + namespace
    # PutMetricData must succeed here: a refusal raises its ClientError and fails the check.
    cw.put_metric_data(
        Namespace=colon_namespace,
        MetricData=[{"MetricName": metric_name, "Value": 1.0, "Unit": "Count"}],
    )

    colon_metrics = _poll_until(
        lambda: cw.list_metrics(Namespace=colon_namespace, MetricName=metric_name)["Metrics"],
        lambda metrics: len(metrics) == 1,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert len(colon_metrics) == 1, f"':'-prefixed namespace metric never appeared: {colon_metrics}"
    assert colon_metrics[0]["Namespace"] == colon_namespace, (
        f"expected Namespace={colon_namespace!r}, got {colon_metrics[0]['Namespace']!r}"
    )
    assert colon_metrics[0]["MetricName"] == metric_name, (
        f"expected MetricName={metric_name!r}, got {colon_metrics[0]['MetricName']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
