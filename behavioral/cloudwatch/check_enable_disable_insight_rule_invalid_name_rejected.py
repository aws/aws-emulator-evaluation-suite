"""enable-disable-insight-rule-invalid-name-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "enable-disable-insight-rule-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

@tags("axis:happy-path", "cap:c1", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DisableInsightRules and EnableInsightRules on a real and a never-created rule name each
    report only the unknown name in Failures[] and move the real rule to DISABLED, then ENABLED;
    the unknown name is never created."""
    cw = ctx.client("cloudwatch")
    real_rule = ctx.unique_name("sim2real-behav-cwprobe-rule-real-endis-")
    bogus_rule = ctx.unique_name("sim2real-behav-cwprobe-rule-missing-endis-")
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-behav-cwprobe-lg-")],
        }
    )
    cw.put_insight_rule(
        RuleName=real_rule,
        RuleDefinition=rule_definition,
        RuleState="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[real_rule]))

    resp = cw.disable_insight_rules(RuleNames=[real_rule, bogus_rule])
    failures = {f["FailureResource"] for f in resp.get("Failures", [])}
    assert failures == {bogus_rule}, (
        f"DisableInsightRules: an unknown rule name must be flagged via Failures without the "
        f"real rule in the same batch being caught up in it, got {resp.get('Failures', [])!r}"
    )
    assert _rule_state(ctx, real_rule) == "DISABLED", (
        "the real rule in the batch must still transition to DISABLED despite the sibling failure"
    )

    resp2 = cw.enable_insight_rules(RuleNames=[real_rule, bogus_rule])
    failures2 = {f["FailureResource"] for f in resp2.get("Failures", [])}
    assert failures2 == {bogus_rule}, (
        f"EnableInsightRules: an unknown rule name must be flagged via Failures without the "
        f"real rule in the same batch being caught up in it, got {resp2.get('Failures', [])!r}"
    )
    assert _rule_state(ctx, real_rule) == "ENABLED", (
        "the real rule in the batch must still transition to ENABLED despite the sibling failure"
    )

    # The unknown name must never have been silently created as a side effect.
    all_rules = cw.describe_insight_rules().get("InsightRules", [])
    assert not any(r["Name"] == bogus_rule for r in all_rules), (
        f"an unknown rule name must never be silently created by Enable/DisableInsightRules, "
        f"got {[r['Name'] for r in all_rules]}"
    )


def _rule_state(ctx, rule_name: str) -> str | None:
    cw = ctx.client("cloudwatch")
    next_token = None
    for _ in range(5):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cw.describe_insight_rules(**kwargs)
        for rule in resp["InsightRules"]:
            if rule["Name"] == rule_name:
                return rule["State"]
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
