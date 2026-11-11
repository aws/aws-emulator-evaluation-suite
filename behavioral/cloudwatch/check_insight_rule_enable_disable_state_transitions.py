"""insight-rule-enable-disable-state-transitions."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "insight-rule-enable-disable-state-transitions"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """PutInsightRule creates a rule in ENABLED state by default; DisableInsightRules/
    EnableInsightRules toggle its State field, and each reports empty per-rule Failures for a
    valid rule name."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-insight-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-") + "*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }

    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=json.dumps(rule_definition),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    created = _find_rule(cw, rule_name)
    assert created is not None, f"expected {rule_name!r} in DescribeInsightRules, found nothing"
    assert created["State"].upper() == "ENABLED", f"expected ENABLED, got {created['State']}"

    disable_resp = cw.disable_insight_rules(RuleNames=[rule_name])
    assert disable_resp.get("Failures", []) == [], (
        f"expected no failures disabling {rule_name!r}, got {disable_resp.get('Failures')}"
    )
    disabled = _find_rule(cw, rule_name)
    assert disabled["State"].upper() == "DISABLED", f"expected DISABLED, got {disabled['State']}"

    enable_resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert enable_resp.get("Failures", []) == [], (
        f"expected no failures enabling {rule_name!r}, got {enable_resp.get('Failures')}"
    )
    enabled = _find_rule(cw, rule_name)
    assert enabled["State"].upper() == "ENABLED", f"expected ENABLED, got {enabled['State']}"


def _find_rule(cw, rule_name):
    paginator_resp = cw.describe_insight_rules(MaxResults=100)
    for rule in paginator_resp.get("InsightRules", []):
        if rule["Name"] == rule_name:
            return rule
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
