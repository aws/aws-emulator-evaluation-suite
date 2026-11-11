"""alarm-mute-rule-lifecycle-create-get-list-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alarm-mute-rule-lifecycle-create-get-list-delete"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule creates a rule visible via Get/List; DeleteAlarmMuteRule removes it (404 after)."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-amr-target-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="sim2real-amr-metric",
        Namespace="Sim2RealBehavioral",
        Period=60,
        Statistic="Average",
        Threshold=100.0,
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    rule_name = ctx.unique_name("sim2real-amr-rule-")
    rule = {"Schedule": {"Expression": "cron(0 2 * * ?)", "Duration": "PT2H", "Timezone": "UTC"}}
    mute_targets = {"AlarmNames": [alarm_name]}

    def _delete_rule():
        try:
            cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFound",
                "ResourceNotFoundException",
            ):
                raise

    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="sim2real behavioral lifecycle check",
        Rule=rule,
        MuteTargets=mute_targets,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_delete_rule)

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert got["Name"] == rule_name, f"expected Name {rule_name}, got {got.get('Name')}"
    assert got["MuteTargets"]["AlarmNames"] == [alarm_name], (
        f"expected MuteTargets.AlarmNames [{alarm_name}], got {got['MuteTargets']}"
    )
    assert got["Rule"]["Schedule"]["Expression"] == "cron(0 2 * * ?)", (
        f"expected Schedule.Expression 'cron(0 2 * * ?)', got {got['Rule']['Schedule']['Expression']!r}"
    )
    # A recurring rule with no ExpireDate cycles between SCHEDULED (outside the daily 02:00-04:00
    # UTC window) and ACTIVE (inside it); it never reaches EXPIRED, which applies only once a rule's
    # own ExpireDate has passed. Asserting the full three-value enum would accept any answer;
    # excluding EXPIRED keeps this falsifiable.
    assert got["Status"] in ("SCHEDULED", "ACTIVE"), (
        f"expected SCHEDULED or ACTIVE for a recurring rule with no ExpireDate, got {got['Status']!r}"
    )
    assert got["MuteType"].upper() == "RECURRING", (
        f"expected RECURRING mute type for a cron schedule, got {got.get('MuteType')!r}"
    )
    assert "AlarmMuteRuleArn" in got and rule_name in got["AlarmMuteRuleArn"], (
        f"expected rule name {rule_name} embedded in AlarmMuteRuleArn, got {got.get('AlarmMuteRuleArn')!r}"
    )
    rule_arn = got["AlarmMuteRuleArn"]

    # AlarmMuteRuleSummary (the shape ListAlarmMuteRules returns) carries no "Name" field --
    # only AlarmMuteRuleArn, ExpireDate, Status, MuteType, LastUpdatedTimestamp -- so summaries
    # are correlated back to the rule we created by ARN, not by a name field that doesn't exist.
    listed = cw.list_alarm_mute_rules(AlarmName=alarm_name).get("AlarmMuteRuleSummaries", [])
    matches = [s for s in listed if s["AlarmMuteRuleArn"] == rule_arn]
    assert len(matches) == 1, f"expected exactly 1 summary for {rule_arn}, found {len(matches)} in {listed}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = cw.list_alarm_mute_rules(AlarmName=alarm_name).get("AlarmMuteRuleSummaries", [])
    assert all(s["AlarmMuteRuleArn"] != rule_arn for s in listed_after), (
        f"deleted mute rule {rule_arn} still present in ListAlarmMuteRules: {listed_after}"
    )


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
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
