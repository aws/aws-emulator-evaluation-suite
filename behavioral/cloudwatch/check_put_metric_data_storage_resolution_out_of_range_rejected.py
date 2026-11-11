"""put-metric-data-storage-resolution-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-storage-resolution-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData rejects a StorageResolution value outside the supported {1, 60} set."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-sr-")
    metric_name = "LatencyMs"

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": 12.5, "StorageResolution": 5}],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == (
        "The parameter MetricData.member.1.StorageResolution must be a value in the set [ 1, 60 ]."
    ), error["Message"]

    # effect absent: no data point was ever accepted under this fresh namespace/metric
    metrics = cw.list_metrics(Namespace=namespace, MetricName=metric_name).get("Metrics", [])
    assert metrics == [], f"expected no metrics after the rejected write, got {metrics!r}"

    # positive control: a supported StorageResolution value succeeds, so the rejection above is
    # specific to the out-of-range value. Its ListMetrics visibility can lag up to ~15 minutes, so
    # only the absence of the rejected write is read back.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 12.5, "StorageResolution": 60}],
    )


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
