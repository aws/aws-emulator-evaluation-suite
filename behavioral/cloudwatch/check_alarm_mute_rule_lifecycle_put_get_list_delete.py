"""alarm-mute-rule-lifecycle-put-get-list-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-mute-rule-lifecycle-put-get-list-delete"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


def _put_recurring_alarm_mute_rule(cw, *, name, description, mute_targets, start_date=None, expire_date=None):
    """Create a recurring alarm mute rule, probing a few valid AWS schedule-expression
    dialects for the nested Rule.Schedule.Expression.

    Real CloudWatch rejects the EventBridge-Rules-style 6-field cron with a "?"
    day-of-month/day-of-week placeholder (``cron(0 12 * * ? *)``) here with
    ValidationError: "The Alarm Mute Rule Schedule expression provided is not valid" --
    despite that being a documented-valid construction for other AWS scheduling APIs.
    Rather than hard-code a single guessed grammar, try a short list of well-formed,
    genuinely-recurring expressions and use the first one real CloudWatch accepts. This
    only corrects the *input* we send; every downstream assertion about the resulting
    rule is unchanged.
    """
    # NOTE: every candidate below carries a complete Duration+Timezone pair.
    # Real CloudWatch's Rule.Schedule structure requires those alongside
    # Expression -- a candidate missing either one fails *local* botocore
    # parameter validation (botocore.exceptions.ParamValidationError) before
    # any request is even sent, which is not a ClientError and would blow
    # past the "except ClientError" fallback below and abort the whole
    # probe on the first structurally-incomplete entry. Keeping every
    # candidate structurally complete (while still varying only the
    # Expression grammar) lets the loop actually probe multiple expression
    # dialects against the real service instead of crashing client-side.
    candidates = [
        {"Expression": "rate(1 day)", "Duration": "PT1H", "Timezone": "UTC"},
        {"Expression": "cron(0 12 * * *)", "Duration": "PT1H", "Timezone": "UTC"},
        {"Expression": "cron(0 12 * * * *)", "Duration": "PT1H", "Timezone": "UTC"},
        {"Expression": "rate(24 hours)", "Duration": "PT1H", "Timezone": "UTC"},
        {"Expression": "cron(0 0 12 * * ?)", "Duration": "PT1H", "Timezone": "UTC"},
    ]

    kwargs = {"Name": name, "Description": description, "MuteTargets": mute_targets}
    if start_date is not None:
        kwargs["StartDate"] = start_date
    if expire_date is not None:
        kwargs["ExpireDate"] = expire_date

    last_err = None
    for schedule in candidates:
        try:
            return cw.put_alarm_mute_rule(Rule={"Schedule": schedule}, **kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationError":
                raise
            last_err = e
    raise last_err


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule is visible via Get/List; DeleteAlarmMuteRule removes it (Get -> 404)."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-mute-target-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-mute-rule-")

    def _delete_rule():
        try:
            cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFound",
                "ResourceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_delete_rule)

    _put_recurring_alarm_mute_rule(
        cw,
        name=rule_name,
        description="sim2real behavioral test mute rule",
        mute_targets={"AlarmNames": [alarm_name]},
    )

    # The mute rule's MuteType classification (ONE_TIME vs RECURRING) is derived
    # server-side from the Rule.Schedule configuration and, like Status, is not
    # guaranteed to be fully materialized in the very first Get immediately
    # after PutAlarmMuteRule returns. Poll briefly rather than asserting on the
    # first read.
    deadline = time.monotonic() + 30.0
    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    while (got.get("MuteType") or "").upper() != "RECURRING" and time.monotonic() < deadline:
        time.sleep(2.0)
        got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    assert got["Name"] == rule_name, f"expected Name {rule_name!r}, got {got.get('Name')!r}"
    assert got["MuteTargets"]["AlarmNames"] == [alarm_name], (
        f"expected MuteTargets.AlarmNames [{alarm_name!r}], got {got.get('MuteTargets')!r}"
    )
    # Real CloudWatch returns the MuteType value lowercased (e.g. "recurring") even
    # though the API documentation shows it as an uppercase enum ("RECURRING"). Compare
    # case-insensitively so the check still asserts the classification is correct without
    # hard-coding a casing convention that the live service doesn't actually follow.
    assert got["MuteType"].upper() == "RECURRING", f"expected RECURRING mute type for a rate/cron schedule, got {got.get('MuteType')!r}"
    assert got["Status"] in ("SCHEDULED", "ACTIVE"), f"expected SCHEDULED or ACTIVE, got {got.get('Status')!r}"
    assert "AlarmMuteRuleArn" in got and rule_name in got["AlarmMuteRuleArn"], (
        f"expected AlarmMuteRuleArn present and containing {rule_name!r}, got {got.get('AlarmMuteRuleArn')!r}"
    )

    # Real CloudWatch's AlarmMuteRuleSummary (the shape returned by
    # ListAlarmMuteRules) does not include a "Name" field at all -- only
    # AlarmMuteRuleArn, ExpireDate, Status, MuteType, and LastUpdatedTimestamp.
    # Identify the summary for this rule the same way the Get response's ARN
    # assertion above does: by the rule name being embedded in the ARN.
    summaries = cw.list_alarm_mute_rules().get("AlarmMuteRuleSummaries", [])
    matching = [s for s in summaries if s["AlarmMuteRuleArn"] == got["AlarmMuteRuleArn"]]
    assert len(matching) == 1, f"expected exactly one summary for {rule_name}, got {len(matching)}"
    assert matching[0]["Status"] == got["Status"], (
        f"expected list summary Status {got['Status']!r} to match Get, got {matching[0].get('Status')!r}"
    )

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    try:
        cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
        raise AssertionError("expected ResourceNotFoundException after delete")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
        expected = ""  # real AWS returns an empty message for this code
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    remaining = cw.list_alarm_mute_rules().get("AlarmMuteRuleSummaries", [])
    assert all(s.get("AlarmMuteRuleArn") != got["AlarmMuteRuleArn"] for s in remaining), (
        f"deleted mute rule {got['AlarmMuteRuleArn']!r} still present in ListAlarmMuteRules"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
