"""insight-rule-delete-nonexistent-reported-in-failures."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "insight-rule-delete-nonexistent-reported-in-failures"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]

_RULE_DEFINITION = {
    "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
    "AggregateOn": "Count",
    "Contribution": {"Filters": [], "Keys": ["$.ip"]},
    "LogFormat": "JSON",
    "LogGroupNames": ["sim2real-behavioral-nonexistent-log-group"],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules with a real rule name and a never-created one deletes the real rule, raises no
    error and lists neither name in Failures: the API reserves Failures for rules that exist but cannot
    be deleted."""
    cw = ctx.client("cloudwatch")
    real_name = ctx.unique_name("sim2real-insight-")
    bogus_name = ctx.unique_name("sim2real-insight-missing-")

    cw.put_insight_rule(
        RuleName=real_name,
        RuleDefinition=json.dumps(_RULE_DEFINITION),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[real_name]))

    resp = cw.delete_insight_rules(RuleNames=[real_name, bogus_name])

    failures = resp.get("Failures", [])
    failed_resources = {f["FailureResource"] for f in failures}
    assert bogus_name not in failed_resources, (
        f"expected deleting a never-created rule name to be silently tolerated (no "
        f"Failures entry), got {failures}"
    )
    assert real_name not in failed_resources, (
        f"the real rule should not itself appear in Failures merely because it was "
        f"deleted alongside a nonexistent name, got {failures}"
    )

    remaining = {r["Name"] for r in cw.describe_insight_rules(MaxResults=100)["InsightRules"]}
    assert real_name not in remaining, "real rule should have been deleted despite the other rule's absence"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
