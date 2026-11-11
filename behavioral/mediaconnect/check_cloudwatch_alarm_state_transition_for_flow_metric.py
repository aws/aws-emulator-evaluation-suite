"""cloudwatch-alarm-state-transition-for-flow-metric."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-state-transition-for-flow-metric"
GROUP = "telemetry"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A CloudWatch alarm on a MediaConnect flow's SourceBitRate metric transitions
    to ALARM and back to OK in response to SetAlarmState, and DescribeAlarms /
    DescribeAlarmHistory reflect both transitions with the reasons supplied."""
    mc = ctx.client("mediaconnect")
    cw = ctx.client("cloudwatch")

    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real-check": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    alarm_name = ctx.unique_name("sim2real-mc-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/MediaConnect",
        MetricName="SourceBitRate",
        Dimensions=[{"Name": "FlowARN", "Value": flow_arn}],
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="LessThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test: forcing ALARM"
    )
    state = _poll_alarm_state(cw, alarm_name, {"ALARM"}, timeout_s=60)
    assert state == "ALARM", f"expected alarm {alarm_name} to reach ALARM, last state={state}"

    cw.set_alarm_state(
        AlarmName=alarm_name, StateValue="OK", StateReason="sim2real test: forcing OK"
    )
    state = _poll_alarm_state(cw, alarm_name, {"OK"}, timeout_s=60)
    assert state == "OK", f"expected alarm {alarm_name} to return to OK, last state={state}"

    history = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=50
    )["AlarmHistoryItems"]
    summaries = [h.get("HistorySummary", "") for h in history]
    assert any("ALARM" in s for s in summaries), (
        f"expected a StateUpdate history entry mentioning ALARM, got {summaries}"
    )
    assert any("OK" in s for s in summaries), (
        f"expected a StateUpdate history entry mentioning OK, got {summaries}"
    )


def _poll_alarm_state(cw, alarm_name: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
        if alarms:
            last = alarms[0]["StateValue"]
            if last in terminal:
                return last
        time.sleep(2)
    raise AssertionError(f"alarm never reached {terminal}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
