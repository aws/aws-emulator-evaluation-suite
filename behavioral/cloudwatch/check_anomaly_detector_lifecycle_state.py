"""anomaly-detector-lifecycle-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "anomaly-detector-lifecycle-state"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector creates a detector that starts untrained and is
    visible via DescribeAnomalyDetectors; DeleteAnomalyDetector removes it (terminal,
    no longer listed)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    metric_name = "InvocationCount"
    spec = {"MetricName": metric_name, "Namespace": namespace, "Stat": "Average"}

    cw.put_anomaly_detector(SingleMetricAnomalyDetector=spec)
    ctx.on_cleanup(lambda: _delete_detector_if_present(cw, SingleMetricAnomalyDetector=spec))

    detector = _find_detector(ctx, namespace, metric_name)
    assert detector is not None, "created anomaly detector not found via DescribeAnomalyDetectors"
    assert detector["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"a freshly created anomaly detector with no training history must be untrained "
        f"(PENDING_TRAINING or TRAINED_INSUFFICIENT_DATA), got {detector['StateValue']!r}"
    )

    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=spec)
    detector_after = _find_detector(ctx, namespace, metric_name)
    assert detector_after is None, "anomaly detector still listed after DeleteAnomalyDetector"


def _find_detector(ctx, namespace: str, metric_name: str):
    cw = ctx.client("cloudwatch")
    resp = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
    for detector in resp.get("AnomalyDetectors", []):
        single = detector.get("SingleMetricAnomalyDetector", {})
        if single.get("Namespace") == namespace and single.get("MetricName") == metric_name:
            return detector
    return None


def _delete_detector_if_present(cw, **spec) -> None:
    """Teardown: delete the detector unless the body already deleted it; any other error raises."""
    try:
        cw.delete_anomaly_detector(**spec)
    except cw.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
