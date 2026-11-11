"""e2e-anomaly-detector-band-drives-alarm-evaluation-teardown."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-anomaly-detector-band-drives-alarm-evaluation-teardown"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With an alarm using the detector's ANOMALY_DETECTION_BAND as ThresholdMetricId,
    DeleteAnomalyDetector succeeds and removes the detector, a second delete fails with
    ResourceNotFoundException "Anomaly detector not found", and the alarm stays until deleted."""
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2Real/AnomalyDetector-")
    metric_name = "RequestLatency"
    alarm_name = ctx.unique_name("sim2real-cwanom-alarm-")

    detector_id = cw.put_anomaly_detector(
        SingleMetricAnomalyDetector={
            "Namespace": namespace,
            "MetricName": metric_name,
            "Stat": "Average",
        }
    )["AnomalyDetectorId"]
    # The check itself deletes the detector, so the cleanup accepts an already-gone detector.
    ctx.on_cleanup(
        lambda: _safe_call(lambda: cw.delete_anomaly_detector(AnomalyDetectorId=detector_id))
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 10.0, "Unit": "Milliseconds"}],
    )

    detectors = cw.describe_anomaly_detectors(AnomalyDetectorIds=[detector_id])["AnomalyDetectors"]
    assert len(detectors) == 1, f"expected exactly one anomaly detector {detector_id}, got {detectors}"
    assert detectors[0]["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"a freshly created detector must be untrained (PENDING_TRAINING or "
        f"TRAINED_INSUFFICIENT_DATA), got {detectors[0]['StateValue']!r}"
    )

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="LessThanLowerOrGreaterThanUpperThreshold",
        EvaluationPeriods=1,
        ThresholdMetricId="ad1",
        Metrics=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric_name},
                    "Period": 60,
                    "Stat": "Average",
                },
                # Real AWS requires exactly two elements of the Metrics list to
                # return data for an anomaly-detection-band alarm: the raw metric
                # stat AND the ANOMALY_DETECTION_BAND expression.
                "ReturnData": True,
            },
            {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)", "ReturnData": True},
        ],
        Tags=[{"Key": "sim2real-owner", "Value": "cw-anom-e2e-teardown"}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm named {alarm_name}, got {alarms}"
    assert alarms[0]["AlarmName"] == alarm_name, (
        f"expected AlarmName={alarm_name!r}, got {alarms[0]['AlarmName']!r}"
    )

    # This is the crux of the check: delete the detector WHILE the alarm still
    # references its band. Real AWS accepts this unconditionally.
    cw.delete_anomaly_detector(AnomalyDetectorId=detector_id)

    remaining_detectors = cw.describe_anomaly_detectors(AnomalyDetectorIds=[detector_id])["AnomalyDetectors"]
    assert remaining_detectors == [], (
        f"detector {detector_id} must be gone from DescribeAnomalyDetectors immediately, "
        f"got {remaining_detectors}"
    )

    # Gone must also mean unusable: a second delete of the same identity is a
    # genuine not-found precondition for DeleteAnomalyDetector (unlike DeleteAlarms,
    # which treats a repeat delete as an idempotent no-op).
    second_delete_code, second_delete_message = _error(
        lambda: cw.delete_anomaly_detector(AnomalyDetectorId=detector_id)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"deleting an already-deleted anomaly detector must fail with "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_message == "Anomaly detector not found", (
        f"expected the exact refusal message 'Anomaly detector not found', got {second_delete_message!r}"
    )

    # The alarm itself is untouched by the detector's removal.
    alarms_after = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms_after) == 1, (
        f"the alarm must survive its anomaly detector's removal, got {alarms_after}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    alarms_final = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert alarms_final == [], f"alarm {alarm_name} must be gone after DeleteAlarms, got {alarms_final}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceNotFoundException"):
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
