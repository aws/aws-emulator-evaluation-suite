"""delete-insight-rules-partial-failure."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-insight-rules-partial-failure"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules naming a real and an unknown rule succeeds, reports neither name in
    Failures[] and deletes the real rule: an unknown name is a no-op."""
    cw = ctx.client("cloudwatch")
    real_rule = ctx.unique_name("sim2real-behav-delrule-")
    bogus_rule = ctx.unique_name("sim2real-behav-missingrule-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-") + "*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=real_rule,
        RuleDefinition=json.dumps(rule_definition),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[real_rule]))

    before = [r["Name"] for r in cw.describe_insight_rules(MaxResults=100)["InsightRules"]]
    assert real_rule in before, (
        f"expected {real_rule} to be listed by describe_insight_rules after put_insight_rule, "
        f"got {before}"
    )

    # DeleteInsightRules succeeds at the top level even though `bogus_rule` does not exist;
    # CloudWatch silently no-ops on the unknown name rather than reporting it as a per-rule
    # failure or rejecting the whole request.
    resp = cw.delete_insight_rules(RuleNames=[real_rule, bogus_rule])
    failures = resp.get("Failures", [])
    failed_names = [f.get("FailureResource") for f in failures]

    assert bogus_rule not in failed_names, (
        f"deleting an unknown insight rule name should be a silent no-op, not a reported "
        f"failure, got {failures}"
    )
    assert real_rule not in failed_names, (
        f"expected {real_rule} to delete cleanly (no Failures entry), got {failures}"
    )

    remaining = cw.describe_insight_rules(MaxResults=100)["InsightRules"]
    remaining_names = [r["Name"] for r in remaining]
    assert real_rule not in remaining_names, "real rule should have been deleted despite the batch containing an unknown name"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
