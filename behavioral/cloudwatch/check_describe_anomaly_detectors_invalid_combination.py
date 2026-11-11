"""describe-anomaly-detectors-invalid-combination."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-anomaly-detectors-invalid-combination"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAnomalyDetectors rejects combining AnomalyDetectorIds with legacy metric filters.

    Positive controls: each filter style works fine on its own (returns without error); only the
    combination of the two mutually-exclusive filter styles is rejected.
    """
    cw = ctx.client("cloudwatch")

    # Positive control 1: legacy single-metric filters alone succeed.
    by_metric = cw.describe_anomaly_detectors(Namespace="AWS/EC2", MetricName="CPUUtilization")
    assert "AnomalyDetectors" in by_metric, (
        f"expected an AnomalyDetectors key in the Namespace/MetricName-filtered response, "
        f"got keys={sorted(by_metric.keys())}"
    )

    # Positive control 2: AnomalyDetectorIds alone succeeds (empty/garbage id -> empty list, no error).
    by_id = cw.describe_anomaly_detectors(AnomalyDetectorIds=[ctx.unique_name("sim2real-ad-id-")])
    assert by_id["AnomalyDetectors"] == [], (
        f"expected an empty result for an unrecognised AnomalyDetectorIds filter, "
        f"got {by_id['AnomalyDetectors']!r}"
    )

    # Negative: combining the two mutually exclusive filter styles is rejected.
    try:
        cw.describe_anomaly_detectors(
            AnomalyDetectorIds=[ctx.unique_name("sim2real-ad-id-")],
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
        )
        raise AssertionError("expected InvalidParameterCombination when mixing filter styles")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
        expected_message = (
            "AnomalyDetectorIds cannot be combined with metric filters (Namespace, MetricName, "
            "Dimensions, AnomalyDetectorTypes, or AnomalyDetectorSearchTerms). Provide either "
            "AnomalyDetectorIds for a direct lookup, or metric filters to list, but not both."
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
