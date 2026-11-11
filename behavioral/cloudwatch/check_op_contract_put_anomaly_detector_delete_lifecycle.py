"""op-contract-putAnomalyDetector-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putAnomalyDetector-delete-lifecycle"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAnomalyDetector creates a single-metric detector that reads back PENDING_TRAINING and is gone
    after DeleteAnomalyDetector, while a call with both SingleMetricAnomalyDetector and
    MetricMathAnomalyDetector raises InvalidParameterCombination with its exact message and creates nothing."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/CWAnomalyDup")
    metric_name = ctx.unique_name("cw-anomalydup-metric-")

    single = {"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"}
    cw.put_anomaly_detector(SingleMetricAnomalyDetector=single)
    ctx.on_cleanup(lambda: _safe_delete_detector(cw, single))


    detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
        "AnomalyDetectors"
    ]
    assert len(detectors) == 1, f"expected 1 detector, got {detectors}"
    assert detectors[0]["StateValue"] == "PENDING_TRAINING", (
        f"expected fresh detector StateValue PENDING_TRAINING, got {detectors[0]['StateValue']}"
    )

    # state transition: EXISTS -> DELETED
    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=single)
    after_delete = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)[
        "AnomalyDetectors"
    ]
    assert after_delete == [], f"detector still present after DeleteAnomalyDetector: {after_delete}"

    # error boundary: SingleMetricAnomalyDetector + MetricMathAnomalyDetector together
    other_metric = ctx.unique_name("cw-anomalydup-conflict-")
    metric_math = {
        "MetricDataQueries": [
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": other_metric, "Dimensions": []},
                    "Period": 60,
                    "Stat": "Average",
                },
                "ReturnData": True,
            }
        ]
    }
    code, message = _error_code(
        lambda: cw.put_anomaly_detector(
            SingleMetricAnomalyDetector={"Namespace": namespace, "MetricName": other_metric, "Stat": "Average"},
            MetricMathAnomalyDetector=metric_math,
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    expected_message = (
        "Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector "
        "can be set, found MetricMathAnomalyDetector, SingleMetricAnomalyDetector."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the forbidden combination must not have created a detector for other_metric
    leftover = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=other_metric)[
        "AnomalyDetectors"
    ]
    assert leftover == [], f"rejected PutAnomalyDetector call unexpectedly created: {leftover}"


def _safe_delete_detector(cw, single_metric_detector):
    try:
        cw.delete_anomaly_detector(SingleMetricAnomalyDetector=single_metric_detector)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
