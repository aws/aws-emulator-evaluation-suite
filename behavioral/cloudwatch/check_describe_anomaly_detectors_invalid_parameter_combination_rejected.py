"""describe-anomaly-detectors-invalid-parameter-combination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-anomaly-detectors-invalid-parameter-combination-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAnomalyDetectors rejects AnomalyDetectorIds combined with metric filters.

    Per the API contract: "If you specify [AnomalyDetectorIds], you cannot also specify
    the Namespace, MetricName, Dimensions, or AnomalyDetectorTypes metric filters."
    """
    cw = ctx.client("cloudwatch")

    # Positive control: the metric-filter style alone succeeds, so the negative below
    # cannot be mistaken for "this account/credentials can't call DescribeAnomalyDetectors
    # at all".
    by_metric = cw.describe_anomaly_detectors(Namespace="AWS/EC2", MetricName="CPUUtilization")
    assert "AnomalyDetectors" in by_metric, by_metric

    code, message = _client_error(
        lambda: cw.describe_anomaly_detectors(
            AnomalyDetectorIds=["sim2real-behav-fake-detector-id"],
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
        )
    )
    assert code == "InvalidParameterCombination", code
    expected_message = (
        "AnomalyDetectorIds cannot be combined with metric filters (Namespace, MetricName, "
        "Dimensions, AnomalyDetectorTypes, or AnomalyDetectorSearchTerms). Provide either "
        "AnomalyDetectorIds for a direct lookup, or metric filters to list, but not both."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
