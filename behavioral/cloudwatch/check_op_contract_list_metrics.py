"""op-contract-listMetrics."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-listMetrics"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics surfaces a metric published via PutMetricData; an invalid RecentlyActive value is rejected."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CW/")
    metric_name = "BehavioralCheckMetric"
    dim_name = "Scenario"
    dim_value = ctx.unique_name("scenario-")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": dim_name, "Value": dim_value}],
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    def _list():
        return cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dim_name, "Value": dim_value}],
        ).get("Metrics", [])

    metrics = _poll_until(_list, lambda m: len(m) >= 1, timeout_s=150, interval_s=6)
    if not metrics:
        raise AssertionError(
            f"metric {metric_name} in namespace {namespace} did not appear in ListMetrics "
            "within the propagation window"
        )
    assert len(metrics) == 1, f"expected exactly 1 metric, got {metrics}"
    metric = metrics[0]
    assert metric["Namespace"] == namespace, f"expected namespace {namespace}, got {metric['Namespace']}"
    assert metric["MetricName"] == metric_name, f"expected metric name {metric_name}, got {metric['MetricName']}"
    expected_dims = [{"Name": dim_name, "Value": dim_value}]
    assert metric["Dimensions"] == expected_dims, f"expected dimensions {expected_dims}, got {metric['Dimensions']}"

    # Real AWS does not enforce a hard cap on the number of Dimensions filters passed to
    # ListMetrics (a batch of 11 filters is accepted, not rejected); the actual validated
    # error boundary is RecentlyActive, which only accepts the literal value "PT3H".

    # Positive control: the only accepted RecentlyActive literal must still surface the
    # metric, so the PT1H rejection below is proven to be a value-specific rejection and
    # not RecentlyActive being refused wholesale.
    recently_active = _poll_until(
        lambda: cw.list_metrics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dim_name, "Value": dim_value}],
            RecentlyActive="PT3H",
        ).get("Metrics", []),
        lambda m: len(m) >= 1,
        timeout_s=150,
        interval_s=6,
    )
    assert recently_active, (
        f"expected RecentlyActive='PT3H' to surface metric {metric_name}, got {recently_active}"
    )

    err, message = _error(lambda: cw.list_metrics(Namespace=namespace, RecentlyActive="PT1H"))
    # CloudWatch's awsQuery protocol reports this exception's wire error code as
    # "InvalidParameterValue" (no "Exception" suffix); botocore surfaces that raw
    # code in exc.response["Error"]["Code"].
    assert err == "InvalidParameterValue", f"expected InvalidParameterValue, got {err}"
    expected = "Request parameter recentlyActive value is invalid"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
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
