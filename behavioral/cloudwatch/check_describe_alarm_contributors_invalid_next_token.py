"""describe-alarm-contributors-invalid-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-invalid-next-token"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors returns InvalidNextToken for a malformed pagination token,
    even when pointed at a genuine multi-timeseries (Metrics Insights) alarm."""
    cw = ctx.client("cloudwatch")

    namespace = "Sim2RealBehavioral"
    metric_name = ctx.unique_name("sim2real-dac-token-metric-")
    alarm_name = ctx.unique_name("sim2real-dac-token-alarm-")

    # A Metrics Insights SELECT/GROUP BY expression alarm is the kind of "multi-timeseries"
    # alarm DescribeAlarmContributors targets, regardless of whether any series currently
    # has live data. Real CloudWatch rejects a GROUP BY expression with no ORDER BY clause
    # ("...only allowed for MetricsInsights expression with an ORDER BY clause"), and for a
    # GROUP BY query the ORDER BY aggregate call must use empty parentheses, referring back
    # to the single aggregate in the SELECT list.
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=1000000.0,
        ActionsEnabled=False,
        Metrics=[{
            "Id": "q1",
            "Expression": (
                f'SELECT AVG("{metric_name}") FROM SCHEMA("{namespace}", Host) '
                f"GROUP BY Host ORDER BY AVG() DESC LIMIT 10"
            ),
            "Period": 60,
            "ReturnData": True,
        }],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Positive control: the account and this exact alarm can otherwise be queried with
    # DescribeAlarmContributors -- a fresh multi-timeseries alarm has no contributors yet,
    # but the call itself succeeds without error. Without this, a target that unconditionally
    # rejects DescribeAlarmContributors for this alarm would be indistinguishable from one that
    # specifically rejects the malformed token.
    control = cw.describe_alarm_contributors(AlarmName=alarm_name)
    assert control.get("AlarmContributors", []) == [], (
        f"expected a brand-new multi-timeseries alarm to have zero contributors, "
        f"got {control.get('AlarmContributors')}"
    )

    code, message = _client_error(
        lambda: cw.describe_alarm_contributors(AlarmName=alarm_name, NextToken="sim2real-not-a-real-token-###")
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = "Invalid NextToken : sim2real-not-a-real-token-###"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
