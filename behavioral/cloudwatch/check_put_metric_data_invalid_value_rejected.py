"""put-metric-data-invalid-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-metric-data-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData must reject a NaN metric value rather than silently accepting or
    dropping it. A positive control with an ordinary value proves the namespace and
    credentials are otherwise healthy before the invalid value is sent."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": "GoodValueMetric", "Value": 1.0}],
    )

    # PutMetricData is one of CloudWatch's original (2010-era) actions; it surfaces this
    # as the short-form "InvalidParameterValue" code on the wire, not the
    # "InvalidParameterValueException" shape name the newer API docs imply.
    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": "BadValueMetric", "Value": float("nan")}],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == "The value NaN for parameter MetricData.member.1.Value is invalid.", error["Message"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
