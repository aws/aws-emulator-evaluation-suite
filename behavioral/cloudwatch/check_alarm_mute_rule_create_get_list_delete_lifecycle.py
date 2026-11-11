"""alarm-mute-rule-create-get-list-delete-lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-mute-rule-create-get-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule creates a rule visible via Get/List; DeleteAlarmMuteRule removes it (404 on Get)."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-mutetarget-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("Sim2RealBehav"),
        MetricName="RequestLatency",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    mute_name = ctx.unique_name("sim2real-muterule-")
    far_future = datetime.now(timezone.utc) + timedelta(days=3650)
    at_expr = f"at({far_future.strftime('%Y-%m-%dT%H:%M')})"

    # AWS rejects StartDate/ExpireDate alongside an "at(...)" schedule expression (the expression
    # itself already fixes the activation time), so only Rule/MuteTargets are set here. The
    # expression is far in the future, so the rule should still come back as SCHEDULED.
    cw.put_alarm_mute_rule(
        Name=mute_name,
        Description="behavioral check mute rule",
        Rule={"Schedule": {"Expression": at_expr, "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_name)))

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name)
    assert got["Name"] == mute_name, f"expected Name {mute_name}, got {got['Name']}"
    # StartDate is far in the future, so the rule must not have taken effect yet.
    assert got["Status"] == "SCHEDULED", f"expected SCHEDULED, got {got['Status']}"
    assert got["MuteType"] == "one-time", f"expected one-time, got {got['MuteType']}"
    assert got["MuteTargets"] == {"AlarmNames": [alarm_name]}, (
        f"expected MuteTargets {{'AlarmNames': [{alarm_name!r}]}}, got {got['MuteTargets']}"
    )
    assert got["Rule"]["Schedule"]["Expression"] == at_expr, (
        f"expected Schedule.Expression {at_expr}, got {got['Rule']['Schedule']['Expression']}"
    )

    # AlarmMuteRuleSummary does not include a Name field (only the ARN), so match on the
    # ARN returned by GetAlarmMuteRule rather than on the rule name.
    listed = cw.list_alarm_mute_rules(AlarmName=alarm_name)["AlarmMuteRuleSummaries"]
    matches = [s for s in listed if s["AlarmMuteRuleArn"] == got["AlarmMuteRuleArn"]]
    assert len(matches) == 1, f"expected exactly 1 summary for {mute_name}, found {len(matches)}"
    assert matches[0]["Status"] == "SCHEDULED", f"expected SCHEDULED, got {matches[0]['Status']}"
    assert matches[0]["MuteType"] == "one-time", f"expected one-time, got {matches[0]['MuteType']}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_name)

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = cw.list_alarm_mute_rules(AlarmName=alarm_name)["AlarmMuteRuleSummaries"]
    assert all(
        s["AlarmMuteRuleArn"] != got["AlarmMuteRuleArn"] for s in listed_after
    ), "deleted mute rule still appears in ListAlarmMuteRules"


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
