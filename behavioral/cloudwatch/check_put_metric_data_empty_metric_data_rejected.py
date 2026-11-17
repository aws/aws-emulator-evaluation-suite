"""put-metric-data-empty-metric-data-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-empty-metric-data-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData with an empty MetricData list is rejected; the identical call with one
    datum succeeds, so the rejection is attributable to the empty list alone."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "EmptyBatchMetric"

    control = cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 1.0, "Unit": "Count"}],
    )
    assert control["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"positive control (one datum) did not return HTTP 200: {control!r}"
    )

    code, message = _error_code(lambda: cw.put_metric_data(Namespace=namespace, MetricData=[]))
    assert code == "MissingParameter", f"expected MissingParameter for an empty MetricData list, got {code}"
    expected = "At least one MetricDatum object must be present in the request."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
