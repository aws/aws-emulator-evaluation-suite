"""alarm-configuration-update-history-on-update."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-configuration-update-history-on-update"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm on an existing alarm with a changed Threshold adds a ConfigurationUpdate
    history item whose HistoryData carries the new threshold; DescribeAlarms returns it too."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cfgupdate-")
    namespace = ctx.unique_name("Sim2RealBehav/")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    def history_items():
        return cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="ConfigurationUpdate")[
            "AlarmHistoryItems"
        ]

    before_items = _poll_until(
        history_items, lambda items: len(items) >= 1, timeout_s=30.0, interval_s=2.0
    )
    before = len(before_items)
    assert before >= 1, "expected a ConfigurationUpdate history item from the initial create"

    new_threshold = 2.5
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=new_threshold,
        ComparisonOperator="GreaterThanThreshold",
    )

    after_items = _poll_until(
        history_items, lambda items: len(items) > before, timeout_s=60.0, interval_s=3.0
    )
    after = len(after_items)
    assert after > before, f"expected ConfigurationUpdate count to grow past {before}, got {after}"

    latest = after_items[0]
    assert str(new_threshold) in latest["HistoryData"], (
        f"expected the new ConfigurationUpdate entry's HistoryData to reflect "
        f"Threshold={new_threshold}, got {latest['HistoryData']!r}"
    )

    updated = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert updated["Threshold"] == new_threshold, (
        f"expected DescribeAlarms to report the updated Threshold={new_threshold}, "
        f"got {updated['Threshold']}"
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
