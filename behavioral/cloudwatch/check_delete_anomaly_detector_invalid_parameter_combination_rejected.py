"""delete-anomaly-detector-invalid-parameter-combination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-anomaly-detector-invalid-parameter-combination-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAnomalyDetector mixing deprecated top-level metric params with
    SingleMetricAnomalyDetector raises InvalidParameterCombination, and the detector
    it would have deleted is left in place."""
    cw = ctx.client("cloudwatch")
    namespace = "sim2real/behavioral"
    metric_name = ctx.unique_name("sim2real-anomaly-metric-")

    single_metric = {
        "MetricName": metric_name,
        "Namespace": namespace,
        "Stat": "Average",
    }
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=single_metric)
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(SingleMetricAnomalyDetector=single_metric)
    )

    # Positive control: the detector the mixed-params call will target actually exists.
    before = cw.describe_anomaly_detectors(
        Namespace=namespace, MetricName=metric_name
    )["AnomalyDetectors"]
    assert len(before) == 1, (
        f"positive control: expected 1 anomaly detector after PutAnomalyDetector, got {len(before)}"
    )

    # Mixing the deprecated Namespace/MetricName/Stat top-level params together with the
    # new-style SingleMetricAnomalyDetector object identifying the same detector.
    error = _client_error(
        lambda: cw.delete_anomaly_detector(
            Namespace=namespace,
            MetricName=metric_name,
            Stat="Average",
            SingleMetricAnomalyDetector=single_metric,
        )
    )
    assert error.get("Code") == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {error.get('Code')!r}"
    )
    expected_message = (
        "Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector "
        "can be set, found single metric attributes, SingleMetricAnomalyDetector."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Independent read at the destination: the rejected call must not have deleted anything.
    after = cw.describe_anomaly_detectors(
        Namespace=namespace, MetricName=metric_name
    )["AnomalyDetectors"]
    assert len(after) == 1, (
        f"a rejected DeleteAnomalyDetector call must not delete the detector, got {len(after)} remaining"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
