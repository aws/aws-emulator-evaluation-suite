"""op-contract-putAnomalyDetector."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-putAnomalyDetector"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector creates a detector that begins PENDING_TRAINING; mixing legacy and typed params is rejected."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CW/")
    metric_name = "AnomalyCheckMetric"

    cw.put_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(Namespace=namespace, MetricName=metric_name, Stat="Average")
    )

    def _find():
        return cw.describe_anomaly_detectors(
            Namespace=namespace, MetricName=metric_name
        ).get("AnomalyDetectors", [])

    detectors = _poll_until(
        _find, lambda d: len(d) >= 1, timeout_s=60, interval_s=5,
        description="anomaly detector visible via DescribeAnomalyDetectors",
    )
    assert len(detectors) == 1, f"expected exactly 1 anomaly detector, got {detectors}"
    detector = detectors[0]
    assert detector["Stat"] == "Average", f"expected Stat Average, got {detector['Stat']}"
    assert detector["Namespace"] == namespace, (
        f"expected Namespace {namespace}, got {detector['Namespace']}"
    )
    assert detector["MetricName"] == metric_name, (
        f"expected MetricName {metric_name}, got {detector['MetricName']}"
    )
    assert detector["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA", "TRAINED"), (
        f"expected a pending/trained StateValue, got {detector['StateValue']}"
    )

    err, message = _error(
        lambda: cw.put_anomaly_detector(
            Namespace=namespace,
            MetricName=metric_name,
            Stat="Average",
            SingleMetricAnomalyDetector={
                "Namespace": namespace,
                "MetricName": metric_name,
                "Stat": "Average",
            },
        )
    )
    # CloudWatch's awsQuery protocol reports this exception's wire error code as
    # "InvalidParameterCombination" (no "Exception" suffix); botocore surfaces that
    # raw code in exc.response["Error"]["Code"].
    assert err == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {err}"
    )
    expected = (
        "Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector "
        "can be set, found single metric attributes, SingleMetricAnomalyDetector."
    )
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # the malformed call must not have created a second detector
    detectors_after = _find()
    assert len(detectors_after) == 1, f"rejected call must not add a detector, got {detectors_after}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
