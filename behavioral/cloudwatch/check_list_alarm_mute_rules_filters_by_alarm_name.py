"""list-alarm-mute-rules-filters-by-alarm-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-alarm-mute-rules-filters-by-alarm-name"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]

# ListAlarmMuteRules filters by AlarmName (and Statuses); this check holds the AlarmName filter
# to the exact set of rules targeting that alarm.


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAlarmMuteRules' AlarmName filter returns exactly the mute rules targeting that alarm."""
    cw = ctx.client("cloudwatch")

    alarm_a = ctx.unique_name("sim2real-cwmr-alarm-a-")
    alarm_b = ctx.unique_name("sim2real-cwmr-alarm-b-")
    for alarm_name in (alarm_a, alarm_b):
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            MetricName="CPUUtilization",
            Namespace="AWS/EC2",
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=90.0,
            ComparisonOperator="GreaterThanThreshold",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_a, alarm_b]))

    schedule = {"Expression": "cron(0 3 * * *)", "Duration": "PT1H"}
    rule_a = ctx.unique_name("sim2real-cwmr-rule-a-")
    rule_b = ctx.unique_name("sim2real-cwmr-rule-b-")
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    cw.put_alarm_mute_rule(Name=rule_a, Rule={"Schedule": schedule}, MuteTargets={"AlarmNames": [alarm_a]}, Tags=tags)
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_a))
    cw.put_alarm_mute_rule(Name=rule_b, Rule={"Schedule": schedule}, MuteTargets={"AlarmNames": [alarm_b]}, Tags=tags)
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_b))

    filtered_a = set(_list_all_mute_rule_names(cw, AlarmName=alarm_a))
    filtered_b = set(_list_all_mute_rule_names(cw, AlarmName=alarm_b))

    assert filtered_a == {rule_a}, f"AlarmName={alarm_a} filter returned {filtered_a}, expected {{{rule_a}}}"
    assert filtered_b == {rule_b}, f"AlarmName={alarm_b} filter returned {filtered_b}, expected {{{rule_b}}}"
    assert rule_b not in filtered_a and rule_a not in filtered_b, "mute rule filter leaked the other alarm's rule"


def _list_all_mute_rule_names(cw, **kwargs):
    # NOTE: empirically, AlarmMuteRuleSummary entries returned by ListAlarmMuteRules do NOT
    # carry a "Name" field (despite some doc examples showing one) -- only AlarmMuteRuleArn,
    # ExpireDate, LastUpdatedTimestamp, MuteType, and Status. The rule name is the last colon-
    # separated segment of the ARN (arn:aws:cloudwatch:<region>:<account>:alarm-mute-rule:<name>).
    names = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = cw.list_alarm_mute_rules(**params)
        for s in resp.get("AlarmMuteRuleSummaries", []):
            if "Name" in s:
                names.append(s["Name"])
            else:
                names.append(s["AlarmMuteRuleArn"].rsplit(":", 1)[-1])
        token = resp.get("NextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
