"""op-contract-deleteAnomalyDetector."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteAnomalyDetector"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAnomalyDetector removes the detector (verified via DescribeAnomalyDetectors);
    a second delete of the same (now-gone) detector fails with ResourceNotFoundException."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "RequestLatency"

    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(lambda: _delete_detector_ignore_missing(cw, namespace, metric_name))

    detectors = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
            "AnomalyDetectors"
        ],
        lambda ds: len(ds) == 1,
        timeout_s=30,
        description="exactly 1 anomaly detector visible after PutAnomalyDetector",
    )
    assert len(detectors) == 1, f"expected exactly 1 anomaly detector, got {len(detectors)}"
    detector = detectors[0]
    assert detector["Stat"] == "Average", f"expected Stat 'Average', got {detector['Stat']!r}"
    assert detector["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA", "TRAINED"), (
        f"unexpected StateValue {detector['StateValue']!r}"
    )

    cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")

    remaining = _poll_until(
        lambda: cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
            "AnomalyDetectors"
        ],
        lambda ds: len(ds) == 0,
        timeout_s=30,
        description="anomaly detector gone after DeleteAnomalyDetector",
    )
    assert remaining == [], "anomaly detector still listed after DeleteAnomalyDetector"

    error = _error(
        lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    )
    assert error == ("ResourceNotFoundException", "Anomaly detector not found"), (
        f"expected the ResourceNotFoundException deleting an already-deleted anomaly detector, got {error!r}"
    )


def _delete_detector_ignore_missing(cw, namespace: str, metric_name: str) -> None:
    try:
        cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"{description} not met within {timeout_s}s; last saw {result!r}")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
