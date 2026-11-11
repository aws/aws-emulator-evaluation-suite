"""delete-insight-rules-partial-failure-reported."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-insight-rules-partial-failure-reported"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules naming an existing and a missing rule succeeds, reports neither name
    in Failures[] and deletes the existing rule: a missing name is a no-op."""
    cw = ctx.client("cloudwatch")
    existing = ctx.unique_name("sim2real-cw-insightrule-")
    missing = ctx.unique_name("sim2real-cw-insightrule-missing-")
    definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": ["/aws/lambda/sim2real-nonexistent-log-group"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=existing,
        RuleDefinition=json.dumps(definition),
        RuleState="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[existing]))

    # DeleteInsightRules succeeds at the top level even though `missing` does not exist;
    # CloudWatch silently no-ops on the unknown name rather than reporting it as a per-rule
    # failure or rejecting the whole request.
    resp = cw.delete_insight_rules(RuleNames=[existing, missing])
    failures = resp.get("Failures", [])
    failed_names = {f["FailureResource"] for f in failures}
    assert missing not in failed_names, (
        f"deleting an unknown insight rule name should be a silent no-op, not a reported "
        f"failure, got {failures}"
    )
    assert existing not in failed_names, f"the existing rule should not have failed: {failures}"

    remaining = _find_rule_names(cw)
    assert existing not in remaining, "the existing rule should have been deleted"


def _find_rule_names(cw):
    names = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = cw.describe_insight_rules(**kwargs)
        names.update(r["Name"] for r in page.get("InsightRules", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
