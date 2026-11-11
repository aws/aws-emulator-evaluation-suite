"""anomaly-detector-created-in-pending-training-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "anomaly-detector-created-in-pending-training-state"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new anomaly detector reports an untrained StateValue (PENDING_TRAINING, or
    TRAINED_INSUFFICIENT_DATA once its first training pass found no history); after
    DeleteAnomalyDetector it is no longer listed and a second delete fails with ResourceNotFoundException."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    metric_name = "RequestLatency"
    spec = {"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"}

    cw.put_anomaly_detector(**spec)
    ctx.on_cleanup(lambda: _delete_if_present(cw, spec))

    resp = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
    detectors = resp["AnomalyDetectors"]
    assert len(detectors) == 1, f"expected exactly one anomaly detector, got {len(detectors)}"
    detector = detectors[0]
    assert detector["Namespace"] == namespace
    assert detector["MetricName"] == metric_name
    assert detector["Stat"] == "Average"
    assert detector["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"expected new anomaly detector StateValue PENDING_TRAINING or TRAINED_INSUFFICIENT_DATA, "
        f"got {detector['StateValue']}"
    )

    cw.delete_anomaly_detector(**spec)
    resp_after = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
    assert resp_after["AnomalyDetectors"] == [], (
        f"expected no anomaly detectors after delete, got {resp_after['AnomalyDetectors']}"
    )
    code, message = _error(lambda: cw.delete_anomaly_detector(**spec))
    assert code == "ResourceNotFoundException", (
        f"expected a second delete of the same anomaly detector identity to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == "Anomaly detector not found", (
        f"expected the exact refusal message 'Anomaly detector not found', got {message!r}"
    )


def _delete_if_present(cw, spec):
    """Teardown: the check deletes the detector itself, so only a not-found is tolerated here."""
    from botocore.exceptions import ClientError

    try:
        cw.delete_anomaly_detector(**spec)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
