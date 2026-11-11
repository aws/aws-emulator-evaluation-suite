"""describe-alarm-history-invalid-history-item-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-history-invalid-history-item-type-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory rejects an unsupported HistoryItemType value with
    ValidationError -- distinct from the InvalidNextToken case that
    covers a bad pagination token."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-alarmhist-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    # Force a real history record so the positive control below has data to find.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real test")

    # --- Negative: an unsupported HistoryItemType value is rejected.
    try:
        result = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="NotARealType")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected an unsupported HistoryItemType to be rejected, got {result!r}")
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'NotARealType' at 'historyItemType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [AlarmContributorAction, "
        "AlarmContributorStateUpdate, Action, StateUpdate, ConfigurationUpdate]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Positive control: the same call with a valid HistoryItemType succeeds
    # and returns the StateUpdate record produced by set_alarm_state above.
    resp = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")
    assert resp["AlarmHistoryItems"], "expected at least one StateUpdate history item"
    for item in resp["AlarmHistoryItems"]:
        assert item["HistoryItemType"] == "StateUpdate", (
            f"expected StateUpdate, got {item['HistoryItemType']!r}"
        )
        assert item["AlarmName"] == alarm_name, (
            f"expected AlarmName {alarm_name!r}, got {item['AlarmName']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
