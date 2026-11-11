"""put-alarm-mute-rule-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

# "Number of Alarm Mute Rules" -- fixed, non-adjustable per-region account quota
# (AWS service quotas for CloudWatch, quota code L-... "Number of Alarm Mute Rules": 2,000).
_QUOTA = 2000


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAlarmMuteRules, the count the 2,000-rule quota is enforced against, starts below the quota,
    grows by exactly one after PutAlarmMuteRule and returns to its starting value after
    DeleteAlarmMuteRule, whose rule then reads as ResourceNotFoundException with an empty message."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_alarm_mute_rule"):
        raise AssertionError(
            "cloudwatch client lacks put_alarm_mute_rule; botocore predates the AlarmMuteRule API"
        )

    before_count = _count_existing_mute_rules(cw)

    # The account must start below the non-adjustable quota; at the quota, PutAlarmMuteRule
    # would reject every new rule with LimitExceededFault.
    assert before_count < _QUOTA, (
        f"account already has {before_count} alarm mute rules, at/above the documented, "
        f"non-adjustable quota of {_QUOTA}; PutAlarmMuteRule should already be rejecting "
        "new rules with LimitExceededFault for this account"
    )

    mute_alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-mutelim-")
    cw.put_metric_alarm(
        AlarmName=mute_alarm,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda _n=mute_alarm: cw.delete_alarms(AlarmNames=[_n]))

    mute_name = ctx.unique_name("sim2real-behav-cwprobe-mutelim-")
    cw.put_alarm_mute_rule(
        Name=mute_name,
        Rule={"Schedule": {"Expression": "at(2030-01-01T00:00)", "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [mute_alarm]},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=mute_name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=_n))

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name)
    assert got.get("Name") == mute_name, f"expected GetAlarmMuteRule to see {mute_name!r}, got {got!r}"

    after_create_count = _count_existing_mute_rules(cw)
    assert after_create_count == before_count + 1, (
        "ListAlarmMuteRules -- the same count PutAlarmMuteRule enforces the "
        f"{_QUOTA}/region quota against -- must report exactly one more rule after "
        f"PutAlarmMuteRule ({before_count} -> {after_create_count})"
    )

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=mute_name)

    try:
        cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name)
        raise AssertionError(f"expected GetAlarmMuteRule({mute_name!r}) to fail after delete")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading a deleted mute rule, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected_message = ""  # AWS returns this refusal with an empty message
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_delete_count = _count_existing_mute_rules(cw)
    assert after_delete_count == before_count, (
        "ListAlarmMuteRules must drop back to the pre-check count -- the same count "
        f"the quota is enforced against -- after delete, expected {before_count}, "
        f"got {after_delete_count}"
    )


def _count_existing_mute_rules(cw) -> int:
    total = 0
    token = None
    while True:
        kwargs = {"MaxRecords": 100}
        if token:
            kwargs["NextToken"] = token
        page = cw.list_alarm_mute_rules(**kwargs)
        total += len(page.get("AlarmMuteRuleSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return total


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
