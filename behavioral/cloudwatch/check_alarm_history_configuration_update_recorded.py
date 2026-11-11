"""alarm-history-configuration-update-recorded."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-history-configuration-update-recorded"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-issuing PutMetricAlarm on an existing alarm with a changed Threshold
    writes a ConfigurationUpdate entry to the alarm's history, and that entry's
    HistoryData reflects the new threshold."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    namespace = ctx.unique_name("sim2real-behav-ns-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="QueueDepth",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    def _config_updates() -> list:
        resp = cw.describe_alarm_history(AlarmName=name, HistoryItemType="ConfigurationUpdate")
        return resp["AlarmHistoryItems"]

    baseline = _poll_until(
        lambda: len(_config_updates()), lambda n: n >= 1, timeout_s=30, interval_s=2
    )

    new_threshold = 90.0
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="QueueDepth",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=new_threshold,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    updated = _poll_until(
        lambda: len(_config_updates()), lambda n: n > baseline, timeout_s=30, interval_s=2
    )
    assert updated > baseline, (
        f"expected a new ConfigurationUpdate history entry after threshold change, "
        f"had {baseline}, now {updated}"
    )

    latest = _config_updates()[0]
    assert latest["HistoryItemType"] == "ConfigurationUpdate", (
        f"expected the newest alarm history item to be ConfigurationUpdate, "
        f"got {latest['HistoryItemType']}"
    )
    assert str(new_threshold) in latest["HistoryData"], (
        f"expected the new threshold {new_threshold} to appear in the "
        f"ConfigurationUpdate HistoryData, got {latest['HistoryData']!r}"
    )

    describe = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert describe["Threshold"] == new_threshold, (
        f"expected updated alarm Threshold to be {new_threshold}, got {describe['Threshold']}"
    )

    cw.delete_alarms(AlarmNames=[name])
    remaining = cw.describe_alarms(AlarmNames=[name]).get("MetricAlarms", [])
    assert remaining == [], (
        f"expected the deleted alarm to be gone from DescribeAlarms, got {remaining}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
