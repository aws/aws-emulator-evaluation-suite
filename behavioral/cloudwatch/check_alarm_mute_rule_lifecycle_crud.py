"""alarm-mute-rule-lifecycle-crud."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-mute-rule-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule creates a rule visible via GetAlarmMuteRule and ListAlarmMuteRules,
    and DeleteAlarmMuteRule removes it from both."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_alarm_mute_rule"):
        raise AssertionError(
            "cloudwatch client lacks put_alarm_mute_rule; botocore predates the AlarmMuteRule API"
        )

    # A real alarm to target with the mute rule (permissions/consistency require both
    # resources exist in a realistic flow, even though the target's existence isn't
    # strictly validated server-side).
    alarm_name = ctx.unique_name("sim2real-mute-target-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2Real/Behavioral",
        MetricName="MuteRuleTargetMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-mute-rule-")
    # A one-time mute window far enough in the future that it stays SCHEDULED for the
    # duration of this check (avoids flakiness around ACTIVE/EXPIRED transitions).
    future = datetime.now(timezone.utc) + timedelta(days=400)
    at_expr = future.strftime("%Y-%m-%dT%H:%M")
    rule = {"Schedule": {"Expression": f"at({at_expr})", "Duration": "PT1H", "Timezone": "UTC"}}
    mute_targets = {"AlarmNames": [alarm_name]}

    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="sim2real behavioral check mute rule",
        Rule=rule,
        MuteTargets=mute_targets,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert got["Name"] == rule_name, f"expected Name {rule_name!r}, got {got['Name']!r}"
    assert got["MuteTargets"]["AlarmNames"] == [alarm_name], (
        f"expected MuteTargets.AlarmNames [{alarm_name!r}], got {got['MuteTargets']['AlarmNames']!r}"
    )
    assert got["Status"] in ("SCHEDULED", "ACTIVE"), got["Status"]
    # A one-time "at(...)" schedule is the "one-time" MuteType, distinct from a recurring
    # "cron(...)"/"rate(...)" rule's "recurring".
    assert got["MuteType"] == "one-time", f"expected MuteType one-time, got {got['MuteType']!r}"

    # AlarmMuteRuleSummary (the shape returned by ListAlarmMuteRules) does not carry a
    # "Name" field -- only "AlarmMuteRuleArn" -- so the rule name has to be recovered
    # from the ARN to correlate list entries back to the rule we created.
    listed = cw.list_alarm_mute_rules(AlarmName=alarm_name)
    names = [_arn_name(s["AlarmMuteRuleArn"]) for s in listed["AlarmMuteRuleSummaries"]]
    assert rule_name in names, f"{rule_name} not found in list_alarm_mute_rules: {names}"

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name)

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = cw.list_alarm_mute_rules(AlarmName=alarm_name)
    names_after = [_arn_name(s["AlarmMuteRuleArn"]) for s in listed_after["AlarmMuteRuleSummaries"]]
    assert rule_name not in names_after, f"{rule_name} still present after delete: {names_after}"


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _arn_name(arn: str) -> str:
    """Recover the resource name from an ARN whose final segment is the name,
    regardless of whether it's colon- or slash-delimited."""
    tail = arn.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
