"""limit-exceeded-family."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)

_INSIGHT_RULE_DEFINITION = json.dumps(
    {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "AggregateOn": "Count",
        "LogGroupNames": ["/aws/lambda/*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.requestId"], "Filters": []},
    }
)

def _list_all_insight_rules(cw):
    rules = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.describe_insight_rules(**kwargs)
        rules.extend(resp.get("InsightRules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return rules

def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """PutCompositeAlarm accepts 100 distinct existing child alarms but rejects 101 ("Too many children in
    AlarmRule, maximum is 100") and a missing child, each with ValidationError and its exact message and no
    alarm created; a mute rule and an insight rule under quota read back as put (MuteTargets, ENABLED)."""
    cw = ctx.client("cloudwatch")
    _tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]

    # PutCompositeAlarm's AlarmRule caps the number of DISTINCT child alarms at 100 (documented,
    # and confirmed below to be about distinct children rather than raw ALARM() occurrences).
    # Isolating that limit from the separate existence check further down needs real, distinct
    # alarms -- 101 of them, so the 101st tips a rule that would otherwise be valid.
    child_alarms = []
    for i in range(101):
        name = ctx.unique_name(f"sim2real-behav-cwprobe-child-{i}-")
        cw.put_metric_alarm(AlarmName=name, Tags=_tags, **_METRIC_ALARM_DEFAULTS)
        child_alarms.append(name)

    def _cleanup_children(_names=tuple(child_alarms)):
        for start in range(0, len(_names), 100):
            cw.delete_alarms(AlarmNames=list(_names[start : start + 100]))

    ctx.on_cleanup(_cleanup_children)
    alarm_name = child_alarms[0]

    # --- Positive control: exactly 100 distinct, existing children succeeds. ---
    ok_composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-ok-")
    ok_rule = " OR ".join(f'ALARM("{n}")' for n in child_alarms[:100])
    cw.put_composite_alarm(AlarmName=ok_composite_name, AlarmRule=ok_rule, Tags=_tags)
    ctx.on_cleanup(lambda _n=ok_composite_name: cw.delete_alarms(AlarmNames=[_n]))
    resp = cw.describe_alarms(AlarmNames=[ok_composite_name], AlarmTypes=["CompositeAlarm"])
    assert [a["AlarmName"] for a in resp.get("CompositeAlarms", [])] == [ok_composite_name], (
        f"PutCompositeAlarm: expected an AlarmRule with exactly 100 distinct existing children "
        f"to be created, got {resp.get('CompositeAlarms')}"
    )

    # --- Negative: 101 distinct, existing children exceeds the 100-child limit. ---
    composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-toobig-")
    too_many_terms = " OR ".join(f'ALARM("{n}")' for n in child_alarms)

    code, message = _err(lambda: cw.put_composite_alarm(AlarmName=composite_name, AlarmRule=too_many_terms))
    assert code == "ValidationError", (
        f"PutCompositeAlarm: expected ValidationError for an AlarmRule referencing 101 distinct "
        f"existing alarms (>100-child limit), got {code}"
    )
    assert message == 'Too many children in AlarmRule, maximum is 100', f"PutCompositeAlarm: unexpected over-limit message {message!r}"
    resp = cw.describe_alarms(AlarmNames=[composite_name], AlarmTypes=["CompositeAlarm"])
    assert resp.get("CompositeAlarms", []) == [], "a rejected PutCompositeAlarm call must not create the alarm"

    # --- Confirms existence, not just count, is independently enforced: a reference (well
    # under the count limit) to an alarm that does NOT exist is also rejected. One reference
    # keeps the message exact: with several, AWS lists the missing alarms in no stable order. ---
    nonexistent_composite_name = ctx.unique_name("sim2real-behav-cwprobe-composite-noexist-")
    ghost_name = ctx.unique_name("sim2real-behav-cwprobe-ghost-")
    ghost_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{ghost_name}"
    nonexistent_rule = f'ALARM("{ghost_name}")'
    nonexistent_code, nonexistent_message = _err(
        lambda: cw.put_composite_alarm(AlarmName=nonexistent_composite_name, AlarmRule=nonexistent_rule)
    )
    assert nonexistent_code == "ValidationError", (
        f"PutCompositeAlarm: expected ValidationError for an AlarmRule referencing alarms that "
        f"do not exist, got {nonexistent_code}"
    )
    assert nonexistent_message == (
        f"Could not save the composite alarm as alarms [{ghost_arn}] in the alarm rule do not exist"
    ), (
        f"PutCompositeAlarm: unexpected nonexistent-reference message {nonexistent_message!r}"
    )
    resp = cw.describe_alarms(AlarmNames=[nonexistent_composite_name], AlarmTypes=["CompositeAlarm"])
    assert resp.get("CompositeAlarms", []) == [], (
        "a rejected PutCompositeAlarm call (nonexistent alarm references) must not create the alarm"
    )

    # --- Supporting well-under-quota exercise of the remaining ops ---

    mute_name = ctx.unique_name("sim2real-behav-cwprobe-mute-")
    cw.put_alarm_mute_rule(
        Name=mute_name,
        Rule={"Schedule": {"Expression": "at(2030-01-01T00:00)", "Duration": "PT1H", "Timezone": "UTC"}},
        MuteTargets={"AlarmNames": [alarm_name]},
        Tags=_tags,
    )
    ctx.on_cleanup(lambda _n=mute_name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=_n))

    def get_mute():
        return cw.get_alarm_mute_rule(AlarmMuteRuleName=mute_name)

    mute_resp = _poll_until(get_mute, lambda r: r.get("Name") == mute_name, timeout_s=30, interval_s=2)
    assert mute_resp.get("MuteTargets") == {"AlarmNames": [alarm_name]}, (
        f"GetAlarmMuteRule: expected MuteTargets to bind {alarm_name}, got {mute_resp.get('MuteTargets')}"
    )

    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=_INSIGHT_RULE_DEFINITION, Tags=_tags)
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))
    enable_resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert enable_resp.get("Failures", []) == [], f"unexpected failure enabling a real rule under quota: {enable_resp}"

    described = [r for r in _list_all_insight_rules(cw) if r.get("Name") == rule_name]
    assert [r.get("State") for r in described] == ["ENABLED"], (
        f"DescribeInsightRules: expected {rule_name} to read back ENABLED after EnableInsightRules, got {described}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
