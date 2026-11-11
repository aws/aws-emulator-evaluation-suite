"""put-anomaly-detector-missing-identification-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-anomaly-detector-missing-identification-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector rejects a call that identifies no metric at all, but succeeds once one is given."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CWAnomalyNeg")
    metric_name = ctx.unique_name("sim2real-anomaly-neg-metric-")

    # negative: no legacy Namespace/MetricName/Stat, no SingleMetricAnomalyDetector, no
    # MetricMathAnomalyDetector -- CloudWatch has nothing to build a model from
    code, message = _error_code(lambda: cw.put_anomaly_detector())
    assert code == "MissingParameter", f"expected MissingParameter, got {code}"
    expected_message = "Input missing required parameter."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the identical intent, with the metric actually identified, succeeds
    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average"))
    detectors_after = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)["AnomalyDetectors"]
    assert len(detectors_after) == 1, f"expected exactly one anomaly detector for {namespace}/{metric_name}, got {detectors_after}"
    assert detectors_after[0]["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"expected new anomaly detector StateValue PENDING_TRAINING or TRAINED_INSUFFICIENT_DATA, "
        f"got {detectors_after[0]['StateValue']}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
