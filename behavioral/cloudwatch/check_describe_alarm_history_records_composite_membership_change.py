"""describe-alarm-history-records-composite-membership-change."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-alarm-history-records-composite-membership-change"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating a composite alarm's AlarmRule to add a child emits a ConfigurationUpdate entry."""
    cw = ctx.client("cloudwatch")
    child1 = ctx.unique_name("sim2real-behav-child1-")
    child2 = ctx.unique_name("sim2real-behav-child2-")
    composite = ctx.unique_name("sim2real-behav-composite-")

    for child in (child1, child2):
        cw.put_metric_alarm(
            AlarmName=child,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            MetricName="CPUUtilization",
            Namespace="AWS/EC2",
            Period=60,
            Statistic="Average",
            Threshold=90.0,
            ActionsEnabled=False,
            TreatMissingData="notBreaching",
        )
        ctx.on_cleanup(lambda n=child: cw.delete_alarms(AlarmNames=[n]))

    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child1}")',
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))

    # Wait for the creation ConfigurationUpdate entry to land, capture baseline count.
    # NOTE: DescribeAlarmHistory defaults AlarmTypes to MetricAlarm-only when omitted, even
    # when AlarmName is given for a composite alarm -- AlarmTypes=["CompositeAlarm"] is
    # required to see composite-alarm history entries at all.
    baseline = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        baseline = cw.describe_alarm_history(
            AlarmName=composite,
            AlarmTypes=["CompositeAlarm"],
            HistoryItemType="ConfigurationUpdate",
        )["AlarmHistoryItems"]
        if len(baseline) >= 1:
            break
        time.sleep(1.0)
    assert len(baseline) >= 1, "expected a ConfigurationUpdate entry for composite alarm creation"
    baseline_count = len(baseline)

    # Update the AlarmRule to add child2.
    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{child1}") OR ALARM("{child2}")',
        ActionsEnabled=False,
    )

    items = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(
            AlarmName=composite,
            AlarmTypes=["CompositeAlarm"],
            HistoryItemType="ConfigurationUpdate",
        )["AlarmHistoryItems"]
        if len(items) > baseline_count:
            break
        time.sleep(1.0)
    assert len(items) > baseline_count, (
        f"expected a new ConfigurationUpdate entry after AlarmRule change, "
        f"baseline={baseline_count} now={len(items)}"
    )

    # The newest entries should mention the newly-added child alarm.
    combined_text = " ".join(
        (it.get("HistorySummary", "") + " " + it.get("HistoryData", "")) for it in items
    )
    assert child2 in combined_text, (
        f"expected new history entry to reference added child alarm {child2}, got: {combined_text}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
