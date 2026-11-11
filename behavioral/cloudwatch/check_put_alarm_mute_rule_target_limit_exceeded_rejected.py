"""put-alarm-mute-rule-target-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-alarm-mute-rule-target-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

#: Fixed per-rule API limit on MuteTargets.AlarmNames (Smithy @length max 100; the
#: PutAlarmMuteRule reference: "Each mute rule can target up to 100 specific alarms by name").
#: It is a constant of the API, identical in every account, not a Service Quotas value.
_MAX_TARGETS = 100
_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_ALARM = dict(
    MetricName="MuteTarget",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=1.0,
    ComparisonOperator="GreaterThanThreshold",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule accepts exactly 100 existing target alarms and rejects 101 with the exact
    ValidationError constraint message: a rejected create stores no rule, a rejected update leaves the
    stored targets and Duration unchanged, and an update to a different 100 targets replaces them."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealMuteTargetLimit")
    alarms = [ctx.unique_name(f"sim2real-mutelim-t{i:03d}-") for i in range(_MAX_TARGETS + 1)]
    for name in alarms:
        cw.put_metric_alarm(AlarmName=name, Namespace=namespace, Tags=_TAGS, **_ALARM)
    ctx.on_cleanup(lambda: _delete_alarms(cw, alarms))

    first_100, all_101 = alarms[:_MAX_TARGETS], alarms
    expected_message = (
        f"1 validation error detected: Value '[{', '.join(all_101)}]' at "
        "'muteTargets.alarmNames' failed to satisfy constraint: Member must have length "
        f"less than or equal to {_MAX_TARGETS}"
    )
    schedule = {"Expression": "at(2099-01-01T00:00)", "Duration": "PT1H", "Timezone": "UTC"}

    # Positive control at the boundary: exactly 100 targets.
    rule = ctx.unique_name("sim2real-mutelim-rule-")
    cw.put_alarm_mute_rule(
        Name=rule, Rule={"Schedule": schedule}, MuteTargets={"AlarmNames": first_100}, Tags=_TAGS
    )
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule))
    got = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule)
    assert sorted(got["MuteTargets"]["AlarmNames"]) == sorted(first_100), (
        f"GetAlarmMuteRule must read back the 100 targets sent, got "
        f"{len(got['MuteTargets']['AlarmNames'])} names: {got['MuteTargets']['AlarmNames'][:3]!r}..."
    )

    # Create with 101 targets: refused, and nothing is stored under the new name.
    over = ctx.unique_name("sim2real-mutelim-over-")
    err = _error(
        lambda: cw.put_alarm_mute_rule(
            Name=over, Rule={"Schedule": schedule}, MuteTargets={"AlarmNames": all_101}, Tags=_TAGS
        )
    )
    ctx.on_cleanup(lambda: _delete_rule_if_present(cw, over))
    assert err["Code"] == "ValidationError", f"expected ValidationError for 101 targets, got {err!r}"
    assert err["Message"] == expected_message, (
        f"expected the 101-target constraint message, got {err['Message'][-200:]!r}"
    )
    missing = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=over))
    assert missing["Code"] == "ResourceNotFoundException", (
        f"a refused PutAlarmMuteRule must store nothing; GetAlarmMuteRule returned {missing!r}"
    )

    # Update with 101 targets and a different Duration: refused, stored rule untouched.
    err = _error(
        lambda: cw.put_alarm_mute_rule(
            Name=rule,
            Rule={"Schedule": {**schedule, "Duration": "PT2H"}},
            MuteTargets={"AlarmNames": all_101},
        )
    )
    assert err["Code"] == "ValidationError", f"expected ValidationError on update, got {err!r}"
    assert err["Message"] == expected_message, (
        f"expected the 101-target constraint message on update, got {err['Message'][-200:]!r}"
    )
    after = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule)
    assert sorted(after["MuteTargets"]["AlarmNames"]) == sorted(first_100), (
        f"a refused update must leave the stored targets unchanged, got "
        f"{len(after['MuteTargets']['AlarmNames'])} names"
    )
    assert after["Rule"]["Schedule"]["Duration"] == "PT1H", (
        f"a refused update must leave the stored Duration unchanged, got "
        f"{after['Rule']['Schedule']['Duration']!r}"
    )

    # Positive control for the update path: a different set of 100 is accepted.
    last_100 = alarms[1:]
    cw.put_alarm_mute_rule(
        Name=rule, Rule={"Schedule": schedule}, MuteTargets={"AlarmNames": last_100}
    )
    updated = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule)
    assert sorted(updated["MuteTargets"]["AlarmNames"]) == sorted(last_100), (
        f"an update to a different 100 targets must replace them, got "
        f"{len(updated['MuteTargets']['AlarmNames'])} names, "
        f"first-sent present={alarms[0] in updated['MuteTargets']['AlarmNames']!r}"
    )


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises: a target that
    accepts what real AWS refuses must fail loudly, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _delete_alarms(cw, names) -> None:
    for start in range(0, len(names), 100):
        cw.delete_alarms(AlarmNames=list(names[start : start + 100]))


def _delete_rule_if_present(cw, name) -> None:
    try:
        cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
