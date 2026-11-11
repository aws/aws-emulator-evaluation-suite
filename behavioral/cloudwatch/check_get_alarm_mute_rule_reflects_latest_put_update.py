"""get-alarm-mute-rule-reflects-latest-put-update."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-alarm-mute-rule-reflects-latest-put-update"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutAlarmMuteRule call fully overwrites (not merges with) the previous rule's
    fields: omitted optional fields disappear rather than retaining their old values."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-cwmr5-alarm-")
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
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-cwmr5-rule-")
    # ExpireDate only supports minute-level precision -- must be provided without seconds.
    far_future_expire = (datetime.now(timezone.utc) + timedelta(days=300)).replace(second=0, microsecond=0)
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="initial-description",
        Rule={"Schedule": {"Expression": "cron(0 3 * * *)", "Duration": "PT1H"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        ExpireDate=far_future_expire,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    v1 = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert v1["Description"] == "initial-description", f"expected initial Description 'initial-description', got {v1.get('Description')!r}"
    assert v1["Rule"]["Schedule"]["Expression"] == "cron(0 3 * * *)", f"expected initial schedule expression 'cron(0 3 * * *)', got {v1['Rule']['Schedule'].get('Expression')!r}"
    assert v1["Rule"]["Schedule"]["Duration"] == "PT1H", f"expected initial schedule duration 'PT1H', got {v1['Rule']['Schedule'].get('Duration')!r}"
    assert "ExpireDate" in v1, "initial ExpireDate was not persisted"

    # Update: same Name, a different schedule, and this time omit Description and ExpireDate
    # entirely. If PutAlarmMuteRule merged instead of overwrote, the stale Description/ExpireDate
    # from v1 would still show up in the Get response.
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Rule={"Schedule": {"Expression": "cron(0 4 * * *)", "Duration": "PT2H"}},
        MuteTargets={"AlarmNames": [alarm_name]},
    )

    v2 = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert v2["Rule"]["Schedule"]["Expression"] == "cron(0 4 * * *)", "updated schedule expression did not persist"
    assert v2["Rule"]["Schedule"]["Duration"] == "PT2H", "updated schedule duration did not persist"
    assert v2.get("Description", "") == "", f"stale Description survived the update: {v2.get('Description')!r}"
    assert "ExpireDate" not in v2, "stale ExpireDate survived the update instead of being cleared by the overwrite"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
