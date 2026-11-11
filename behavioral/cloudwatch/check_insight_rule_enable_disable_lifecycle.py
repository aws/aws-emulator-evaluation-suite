"""insight-rule-enable-disable-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "insight-rule-enable-disable-lifecycle"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DisableInsightRules/EnableInsightRules flip the rule's State field."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-cw-insightrule-")
    definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": ["/aws/lambda/sim2real-nonexistent-log-group"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=json.dumps(definition),
        RuleState="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    rule = _find_rule(cw, rule_name)
    assert rule["State"] == "ENABLED", f"expected newly created rule ENABLED, got {rule['State']}"

    resp = cw.disable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"expected no disable failures, got {resp.get('Failures')}"
    rule = _find_rule(cw, rule_name)
    assert rule["State"] == "DISABLED", f"expected DISABLED after disable, got {rule['State']}"

    resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"expected no enable failures, got {resp.get('Failures')}"
    rule = _find_rule(cw, rule_name)
    assert rule["State"] == "ENABLED", f"expected ENABLED after re-enable, got {rule['State']}"


def _find_rule(cw, rule_name):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = cw.describe_insight_rules(**kwargs)
        for rule in page.get("InsightRules", []):
            if rule["Name"] == rule_name:
                return rule
        next_token = page.get("NextToken")
        if not next_token:
            break
    raise AssertionError(f"insight rule {rule_name} not found in DescribeInsightRules")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
