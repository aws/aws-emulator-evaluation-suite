"""describe-alarm-history-includes-actions-taken-telemetry."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-alarm-history-includes-actions-taken-telemetry"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """SetAlarmState to ALARM on an alarm with an SNS action records a StateUpdate history item and
    an Action item naming the topic ARN as notificationResource with actionState Succeeded."""
    cw = ctx.client("cloudwatch")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-ahact-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    alarm_name = ctx.unique_name("sim2real-behav-ahact-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="ActionsTakenProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        AlarmActions=[topic_arn],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="forced for behavioral check")

    state_item = _poll_for_history_item(cw, alarm_name, "StateUpdate")
    state_combined = state_item["HistorySummary"] + state_item.get("HistoryData", "")
    assert "ALARM" in state_combined, (
        f"StateUpdate history item does not mention the ALARM transition: {state_combined!r}"
    )

    action_item = _poll_for_history_item(cw, alarm_name, "Action")
    combined = action_item.get("HistorySummary", "") + action_item.get("HistoryData", "")
    assert topic_arn in combined, (
        f"Action history item does not name the invoked action ARN: {combined!r}"
    )
    action_data = json.loads(action_item["HistoryData"])
    assert action_data.get("notificationResource") == topic_arn, (
        f"Action history item's notificationResource does not match the invoked action ARN: {action_data!r}"
    )
    assert action_data.get("actionState") == "Succeeded" and action_data.get("error") is None, (
        f"Action history item does not report the action outcome as succeeded: {action_data!r}"
    )


def _poll_for_history_item(cw, alarm_name: str, item_type: str, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType=item_type, ScanBy="TimestampDescending"
        )
        items = resp.get("AlarmHistoryItems", [])
        if items:
            return items[0]
        time.sleep(3)
    raise AssertionError(f"no {item_type} alarm history item ever appeared for {alarm_name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
