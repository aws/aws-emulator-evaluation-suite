"""disable-alarm-actions-still-records-state-history."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disable-alarm-actions-still-records-state-history"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With alarm actions disabled, SetAlarmState still records a StateUpdate history entry."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-disabled-actions-")

    cw.put_metric_alarm(
        AlarmName=name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Period=60,
        Statistic="Average",
        Threshold=90.0,
        ActionsEnabled=True,
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    cw.disable_alarm_actions(AlarmNames=[name])

    described = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(described) == 1, f"expected exactly one alarm named {name!r}, got {described!r}"
    assert described[0]["ActionsEnabled"] is False, "ActionsEnabled should be False after DisableAlarmActions"

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="behavioral-disabled-actions-test")

    # ActionsEnabled must remain False -- SetAlarmState must not silently re-enable actions.
    described_after = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert described_after[0]["ActionsEnabled"] is False, (
        f"ActionsEnabled flipped back to True after SetAlarmState, got {described_after[0]!r}"
    )

    items = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate")[
            "AlarmHistoryItems"
        ]
        if any("ALARM" in it.get("HistorySummary", "") for it in items):
            break
        time.sleep(1.0)

    assert any("ALARM" in it.get("HistorySummary", "") for it in items), (
        f"expected a StateUpdate history entry reflecting the ALARM transition, got: {items}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
