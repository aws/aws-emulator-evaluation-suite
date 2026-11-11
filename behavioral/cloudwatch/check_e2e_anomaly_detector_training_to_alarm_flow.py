"""e2e-anomaly-detector-training-to-alarm-flow."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "e2e-anomaly-detector-training-to-alarm-flow"
GROUP = "e2e"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After an anomaly detector trained on stable baseline data leaves PENDING_TRAINING, an alarm
    on its ANOMALY_DETECTION_BAND(m1, 2) reaches ALARM once a clearly out-of-band datapoint
    (5000) is published."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavAnomaly")
    metric_name = "SteadyBaselineMetric"
    alarm_name = ctx.unique_name("sim2real-cwad-alarm-")

    _seed_baseline(ctx, namespace, metric_name)

    cw.put_anomaly_detector(
        SingleMetricAnomalyDetector={"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"}
    )
    ctx.on_cleanup(
        lambda: cw.delete_anomaly_detector(
            SingleMetricAnomalyDetector={"Namespace": namespace, "MetricName": metric_name, "Stat": "Average"}
        )
    )

    trained_state = _poll_detector_state(
        ctx, namespace, metric_name, {"TRAINED", "TRAINED_INSUFFICIENT_DATA"}, timeout_s=900.0
    )
    assert trained_state in {"TRAINED", "TRAINED_INSUFFICIENT_DATA"}, (
        f"anomaly detector never left PENDING_TRAINING, last state {trained_state}"
    )

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="GreaterThanUpperThreshold",
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
                "ReturnData": True,
            },
            {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)", "ReturnData": True},
        ],
        TreatMissingData="notBreaching",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    deadline = time.monotonic() + 300.0
    state = None
    while time.monotonic() < deadline:
        cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": metric_name, "Value": 5000.0}])
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        if state == "ALARM":
            break
        time.sleep(20.0)
    assert state == "ALARM", (
        f"alarm did not transition to ALARM off the trained anomaly band, last state {state}"
    )


def _seed_baseline(ctx, namespace: str, metric_name: str) -> None:
    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)
    points = []
    for i in range(80):
        ts = now - timedelta(minutes=2 * i)
        value = 10.0 + (i % 3) * 0.5
        points.append({"MetricName": metric_name, "Timestamp": ts, "Value": value})
    for i in range(0, len(points), 20):
        cw.put_metric_data(Namespace=namespace, MetricData=points[i : i + 20])


def _poll_detector_state(ctx, namespace: str, metric_name: str, target_states, timeout_s: float = 900.0, interval_s: float = 30.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        detectors = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)["AnomalyDetectors"]
        if detectors:
            last = detectors[0]["StateValue"]
            if last in target_states:
                return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
