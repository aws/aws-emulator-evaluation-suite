"""list-alarm-mute-rules-invalid-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-alarm-mute-rules-invalid-next-token"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAlarmMuteRules given a NextToken minted three pages deep under an AlarmName filter, replayed
    on an unfiltered call, returns a well-formed page (summaries with AlarmMuteRuleArn, NextToken a
    string or absent) instead of an error, and all five mute rules stay listable afterwards."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "list_alarm_mute_rules") or not hasattr(cw, "put_alarm_mute_rule"):
        raise AssertionError(
            "cloudwatch client lacks list_alarm_mute_rules/put_alarm_mute_rule; botocore predates the AlarmMuteRule API"
        )

    from datetime import datetime, timedelta, timezone

    future = datetime.now(timezone.utc) + timedelta(days=400)
    at_expr = future.strftime("%Y-%m-%dT%H:%M")

    def _make_alarm(name, metric_name):
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace="Sim2Real/Behavioral",
            MetricName=metric_name,
            Statistic="Average",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
        )
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    def _make_rules(target_alarm_name, count, prefix):
        names = []
        for i in range(count):
            rule_name = ctx.unique_name(f"{prefix}{i}-")
            names.append(rule_name)
            cw.put_alarm_mute_rule(
                Name=rule_name,
                Description="sim2real behavioral check mute rule (invalid next token)",
                Rule={"Schedule": {"Expression": f"at({at_expr})", "Duration": "PT1H", "Timezone": "UTC"}},
                MuteTargets={"AlarmNames": [target_alarm_name]},
            )
        ctx.on_cleanup(lambda: [cw.delete_alarm_mute_rule(AlarmMuteRuleName=n) for n in names])
        return names

    def _wait_for_full_count(target_alarm_name, expected):
        def _check():
            resp = cw.list_alarm_mute_rules(AlarmName=target_alarm_name, MaxRecords=max(expected * 2, 10))
            summaries = resp.get("AlarmMuteRuleSummaries", [])
            return len(summaries) == expected and not resp.get("NextToken")

        _poll_until(_check, timeout=30, interval=2)

    # Five mute rules on one alarm -- enough to walk three successive
    # single-item pages deep and still have a NextToken, i.e. mint a
    # genuine, well-formed token a few items into real pagination.
    alarm_name = ctx.unique_name("sim2real-mute-token-")
    _make_alarm(alarm_name, "MuteTokenMetric")
    _make_rules(alarm_name, 5, "sim2real-mute-token-rule-")
    _wait_for_full_count(alarm_name, 5)

    deep_token = None
    for _ in range(3):
        kwargs = {"AlarmName": alarm_name, "MaxRecords": 1}
        if deep_token:
            kwargs["NextToken"] = deep_token
        resp = cw.list_alarm_mute_rules(**kwargs)
        deep_token = resp.get("NextToken")
        assert deep_token, "expected pagination to continue given 5 total mute rules on the alarm"

    # Replay the filtered-listing token on an unfiltered call (no AlarmName): AWS does not raise
    # InvalidNextToken for it, so the call must succeed with a well-formed page.
    resp = cw.list_alarm_mute_rules(MaxRecords=1, NextToken=deep_token)

    summaries = resp.get("AlarmMuteRuleSummaries")
    assert isinstance(summaries, list), f"expected a well-formed AlarmMuteRuleSummaries list, got {summaries!r}"
    for item in summaries:
        assert isinstance(item, dict) and "AlarmMuteRuleArn" in item, (
            f"expected a well-formed mute rule summary, got {item!r}"
        )

    next_token = resp.get("NextToken")
    assert next_token is None or isinstance(next_token, str), (
        f"expected NextToken to be a string or absent, got {next_token!r}"
    )

    # And confirm the mismatched replay had no destructive side effects: all
    # five mute rules created for this check are still present and listable.
    _wait_for_full_count(alarm_name, 5)


def _poll_until(predicate, timeout=30, interval=2):
    import time

    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - keep polling through transient errors
            last_exc = exc
        time.sleep(interval)
    if last_exc is not None:
        raise last_exc
    raise AssertionError("condition not met within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


