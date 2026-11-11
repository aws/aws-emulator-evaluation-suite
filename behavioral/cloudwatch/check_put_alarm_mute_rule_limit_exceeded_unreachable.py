"""put-alarm-mute-rule-limit-exceeded-unreachable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-limit-exceeded-unreachable"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule for a one-time 2030 schedule reads back from GetAlarmMuteRule with its Name, an ARN
    ending in :alarm-mute-rule:<name>, MuteType one-time, Status SCHEDULED and the MuteTargets, and a
    second Put on the same Name updates the Duration (PT3H) and Description in place."""
    cw = ctx.client("cloudwatch")

    rule_name = ctx.unique_name("sim2real-behav-cw-muterule-limit-")
    target_alarm = ctx.unique_name("sim2real-behav-cw-mutetarget-alarm-")
    put_resp = cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="behavioral check: quota boundary probe",
        Rule={"Schedule": {"Expression": "at(2030-06-01T00:00)", "Duration": "PT2H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [target_alarm]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))
    # PutAlarmMuteRuleOutput does not itself return the rule's ARN; fetch it via
    # GetAlarmMuteRule, which does include AlarmMuteRuleArn.
    assert put_resp is not None, "PutAlarmMuteRule returned no response body"

    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert got["Name"] == rule_name, f"expected Name={rule_name!r}, got {got['Name']!r}"
    assert got["AlarmMuteRuleArn"].endswith(f":alarm-mute-rule:{rule_name}"), (
        f"unexpected AlarmMuteRuleArn shape: {got['AlarmMuteRuleArn']!r}"
    )
    assert got["MuteType"] == "one-time", f"expected one-time, got {got['MuteType']!r}"
    assert got["Status"] == "SCHEDULED", f"a rule scheduled for 2030 must still be SCHEDULED, got {got['Status']!r}"
    assert got["MuteTargets"]["AlarmNames"] == [target_alarm], (
        f"expected MuteTargets.AlarmNames=[{target_alarm!r}], got {got['MuteTargets']!r}"
    )

    # Re-putting the same Name updates the existing rule in place rather than erroring,
    # exercising the documented create-or-update (upsert) contract of PutAlarmMuteRule.
    cw.put_alarm_mute_rule(
        Name=rule_name,
        Description="behavioral check: quota boundary probe (updated)",
        Rule={"Schedule": {"Expression": "at(2030-06-01T00:00)", "Duration": "PT3H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [target_alarm]},
    )
    updated = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    assert updated["Rule"]["Schedule"]["Duration"] == "PT3H", "PutAlarmMuteRule must update the existing rule in place"
    assert updated["Description"] == "behavioral check: quota boundary probe (updated)", (
        f"expected updated Description, got {updated['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
