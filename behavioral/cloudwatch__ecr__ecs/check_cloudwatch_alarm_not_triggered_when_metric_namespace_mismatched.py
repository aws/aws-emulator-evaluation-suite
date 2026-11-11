"""cloudwatch-alarm-not-triggered-when-metric-namespace-mismatched."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-not-triggered-when-metric-namespace-mismatched"
GROUP = "metrics-delivery"
SERVICES = ["cloudwatch", "ecr", "ecs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm on a metric/dimension pair that never receives data stays INSUFFICIENT_DATA with no
    ALARM transition in its history, while a control alarm on a published metric reaches ALARM."""
    cw = ctx.client("cloudwatch")
    ecs = ctx.client("ecs")

    cluster = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster))

    # --- broken: AWS/ECS CPUUtilization for a ClusterName/ServiceName pair that
    # never ran a task, so CloudWatch never has a datapoint for it.
    broken_alarm = ctx.unique_name("sim2real-alarm-mismatch-")
    cw.put_metric_alarm(
        AlarmName=broken_alarm,
        Namespace="AWS/ECS",
        MetricName="CPUUtilization",
        Dimensions=[
            {"Name": "ClusterName", "Value": cluster},
            {"Name": "ServiceName", "Value": "sim2real-service-that-never-existed"},
        ],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[broken_alarm]))

    # --- positive control: a real custom metric that we actually publish and
    # that clears the threshold.
    namespace = ctx.unique_name("Sim2RealNamespace")
    metric_name = "ControlMetric"
    control_alarm = ctx.unique_name("sim2real-alarm-control-")
    cw.put_metric_alarm(
        AlarmName=control_alarm,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_alarm]))

    now = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 5.0, "Unit": "Count"}],
    )

    control_state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[control_alarm])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=300,
        interval_s=15,
    )
    assert control_state == "ALARM", f"positive control never reached ALARM (state={control_state})"

    # The broken alarm gets the same wall-clock opportunity to (incorrectly)
    # transition; it must not.
    broken_state = cw.describe_alarms(AlarmNames=[broken_alarm])["MetricAlarms"][0]["StateValue"]
    assert broken_state == "INSUFFICIENT_DATA", (
        f"alarm on a namespace/dimension combo with no data was not INSUFFICIENT_DATA: {broken_state}"
    )

    broken_history = cw.describe_alarm_history(AlarmName=broken_alarm, HistoryItemType="StateUpdate")[
        "AlarmHistoryItems"
    ]
    summaries = [h["HistorySummary"] for h in broken_history]
    assert not any("to ALARM" in s for s in summaries), f"mismatched-metric alarm recorded an ALARM transition: {summaries}"


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
