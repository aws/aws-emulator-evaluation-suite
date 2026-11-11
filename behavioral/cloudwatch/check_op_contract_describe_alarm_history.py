"""op-contract-describeAlarmHistory."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describeAlarmHistory"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory records a StateUpdate history item for each SetAlarmState
    transition, retrievable by AlarmName + HistoryItemType; an expired/invalid NextToken is
    rejected with InvalidNextToken."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-alarm-")
    namespace = ctx.unique_name("sim2real-cw-ns-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ErrorCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="sim2real behavioral check forced ALARM",
    )

    items = _poll_until(
        lambda: cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate"
        )["AlarmHistoryItems"],
        lambda its: len(its) >= 1,
        timeout_s=30,
    )
    assert len(items) >= 1, "expected at least one StateUpdate history item after SetAlarmState"
    assert all(it["AlarmName"] == alarm_name for it in items), items
    assert all(it["HistoryItemType"] == "StateUpdate" for it in items), items
    assert any("ALARM" in it["HistorySummary"] for it in items), items

    code, message = _client_error(
        lambda: cw.describe_alarm_history(AlarmName=alarm_name, NextToken="not-a-real-token")
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = "Invalid NextToken : not-a-real-token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
