"""op-contract-deleteAnomalyDetector-dup."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteAnomalyDetector-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAnomalyDetector removes a detector created via SingleMetricAnomalyDetector,
    but is rejected with MissingParameter when no identifying fields are supplied at
    all -- and the real detector is left untouched by the rejected call."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-ns-")
    metric_name = "AnomalyMetric"
    detector = {"MetricName": metric_name, "Namespace": namespace, "Stat": "Average"}

    cw.put_anomaly_detector(SingleMetricAnomalyDetector=detector)
    ctx.on_cleanup(lambda: _safe_delete_detector(ctx, detector))

    def _detector_present() -> bool:
        found = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
        return len(found["AnomalyDetectors"]) == 1

    assert _poll_until(_detector_present, timeout_s=20.0), "detector should be visible after creation"

    # error boundary: omitting AnomalyDetectorId, SingleMetricAnomalyDetector,
    # MetricMathAnomalyDetector, AND the deprecated Namespace/MetricName/Stat trio
    # is rejected with MissingParameter -- and it leaves the detector untouched.
    code, message = _error(lambda: cw.delete_anomaly_detector())
    assert code == "MissingParameter", f"expected MissingParameter, got {code!r}"
    expected_message = (
        "Either an AnomalyDetectorId or a metric definition must be provided to identify the "
        "anomaly detector to delete."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _detector_present(), "detector must still exist after the rejected call"

    # success-path contract: deleting with the correct identifying fields removes it.
    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=detector)

    def _detector_gone() -> bool:
        return not _detector_present()

    assert _poll_until(_detector_gone, timeout_s=20.0), "detector should be gone after DeleteAnomalyDetector"


def _safe_delete_detector(ctx: Any, detector: dict) -> None:
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    try:
        cw.delete_anomaly_detector(SingleMetricAnomalyDetector=detector)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, timeout_s: float = 30.0, interval_s: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return False


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
