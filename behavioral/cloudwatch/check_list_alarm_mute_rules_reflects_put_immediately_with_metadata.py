"""list-alarm-mute-rules-reflects-put-immediately-with-metadata."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-alarm-mute-rules-reflects-put-immediately-with-metadata"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created alarm mute rule shows up in ListAlarmMuteRules immediately (no
    propagation delay) with accurate ARN/Status/MuteType/LastUpdatedTimestamp metadata."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-behav-amr-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="MuteRuleProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-behav-amr-")
    start_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    before_put = datetime.now(timezone.utc)
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="sim2real behavioral check mute rule",
        Rule={
            "Schedule": {
                "Expression": f"at({start_at.strftime('%Y-%m-%dT%H:%M')})",
                "Duration": "PT30M",
                "Timezone": "UTC",
            }
        },
        MuteTargets={"AlarmNames": [alarm_name]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))
    after_put = datetime.now(timezone.utc)

    resp = cw.list_alarm_mute_rules(AlarmName=alarm_name)
    matches = [
        s
        for s in resp["AlarmMuteRuleSummaries"]
        if s["AlarmMuteRuleArn"].endswith(f":alarm-mute-rule/{rule_name}")
        or s["AlarmMuteRuleArn"].endswith(f":alarm-mute-rule:{rule_name}")
    ]
    assert len(matches) == 1, (
        f"expected exactly one mute rule summary for {rule_name!r}, got "
        f"{resp['AlarmMuteRuleSummaries']}"
    )
    summary = matches[0]

    assert summary["Status"] == "SCHEDULED", summary["Status"]
    assert summary["MuteType"] == "one-time", summary["MuteType"]
    last_updated = summary["LastUpdatedTimestamp"]
    assert before_put <= last_updated.replace(tzinfo=timezone.utc) <= after_put + timedelta(seconds=5), (
        f"LastUpdatedTimestamp {last_updated} not within the PutAlarmMuteRule call window "
        f"[{before_put}, {after_put}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
