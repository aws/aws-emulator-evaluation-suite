"""alarm-history-records-configuration-update."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-history-records-configuration-update"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-issuing PutMetricAlarm for an existing alarm with a changed Threshold
    overwrites its configuration and appends a ConfigurationUpdate entry to
    DescribeAlarmHistory whose HistoryData reflects the new threshold."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cw-confupdate-")
    namespace = "Sim2Real/BehavioralCheck"
    metric_name = ctx.unique_name("ConfUpdateMetric-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    baseline_count = len(
        cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="ConfigurationUpdate")[
            "AlarmHistoryItems"
        ]
    )

    new_threshold = 250.5
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=new_threshold,
        ComparisonOperator="GreaterThanThreshold",
    )

    items = _poll_history_grew(cw, alarm_name, baseline_count, timeout_s=30.0)
    assert items is not None, "no new ConfigurationUpdate history item appeared after the update"
    latest = items[0]
    assert latest["HistoryItemType"] == "ConfigurationUpdate"
    assert str(new_threshold) in latest["HistoryData"], "updated threshold not reflected in history data"

    updated = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert updated["Threshold"] == new_threshold


def _poll_history_grew(cw, alarm_name, baseline_count, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="ConfigurationUpdate")[
            "AlarmHistoryItems"
        ]
        if len(items) > baseline_count:
            return items
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
