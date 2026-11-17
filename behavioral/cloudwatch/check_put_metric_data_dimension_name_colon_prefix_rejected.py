"""put-metric-data-dimension-name-colon-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-dimension-name-colon-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


def expect_error(fn, code, message, label="call"):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"{label}: expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"{label}: expected {(code, message)!r}, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


@tags("axis:rejection", "cap:c1", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData refuses a dimension Name starting with ':'; the same name with the colon
    dropped is accepted and later found in ListMetrics, while the refused name never is."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-dimcolon-")
    metric_name = ctx.unique_name("cw-dimcolon-metric-")
    dim_value = ctx.unique_name("dim-")
    rejected_name = ":" + ctx.unique_name("Env")
    legal_name = rejected_name[1:]

    _COLON_PREFIX = (
        "InvalidParameterValue",
        "The value : for parameter MetricData.member.1.Dimensions.member.1.Name is invalid.",
    )
    expect_error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{
                "MetricName": metric_name,
                "Dimensions": [{"Name": rejected_name, "Value": dim_value}],
                "Value": 1.0,
                "Unit": "Count",
            }],
        ),
        *_COLON_PREFIX,
        label="PutMetricData with a ':'-prefixed dimension Name",
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{
            "MetricName": metric_name,
            "Dimensions": [{"Name": legal_name, "Value": dim_value}],
            "Value": 1.0,
            "Unit": "Count",
        }],
    )

    legal_metrics = _poll_until(
        lambda: cw.list_metrics(
            Namespace=namespace, MetricName=metric_name,
            Dimensions=[{"Name": legal_name, "Value": dim_value}],
        )["Metrics"],
        lambda metrics: len(metrics) == 1,
    )
    assert len(legal_metrics) == 1, (
        f"legal-neighbour dimension never appeared in ListMetrics, last={legal_metrics}"
    )
    assert legal_metrics[0]["Dimensions"] == [{"Name": legal_name, "Value": dim_value}], (
        f"expected Dimensions=[{{'Name': {legal_name!r}, 'Value': {dim_value!r}}}], "
        f"got {legal_metrics[0]['Dimensions']!r}"
    )

    rejected_metrics = cw.list_metrics(
        Namespace=namespace, MetricName=metric_name,
        Dimensions=[{"Name": rejected_name, "Value": dim_value}],
    )["Metrics"]
    assert rejected_metrics == [], f"the refused dimension appeared in ListMetrics: {rejected_metrics}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
