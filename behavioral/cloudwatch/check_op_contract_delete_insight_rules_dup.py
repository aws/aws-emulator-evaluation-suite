"""op-contract-deleteInsightRules-dup."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-deleteInsightRules-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules with a real rule and a never-created name succeeds with empty Failures and
    removes the real rule, while a malformed rule name sent alone is reported in Failures with
    FailureCode INVALID_RULE_NAME."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-cw-rule-")
    missing_name = ctx.unique_name("sim2real-behav-cw-rule-missing-")
    malformed_name = "bad rule name"
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-behav-cw-lg-")],
        }
    )
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=rule_definition)
    ctx.on_cleanup(lambda: _safe_delete_rules(ctx, [rule_name]))

    # success-path contract: deleting a real rule together with a nonexistent name
    # succeeds overall (no exception) and the real rule is actually removed. Failures[]
    # is reserved for rules that exist but cannot be deleted, so a never-created name is a
    # silent no-op rather than a reported failure.
    resp = cw.delete_insight_rules(RuleNames=[rule_name, missing_name])
    failures = {f["FailureResource"] for f in resp["Failures"]}
    assert failures == set(), (
        f"expected a never-created rule name to be a silent no-op, not a reported failure, "
        f"got {resp['Failures']!r}"
    )

    remaining_names = {r["Name"] for r in cw.describe_insight_rules()["InsightRules"]}
    assert rule_name not in remaining_names, "deleted rule must not be listed anymore"

    # error boundary: a syntactically malformed rule name is refused per name in Failures[].
    resp2 = cw.delete_insight_rules(RuleNames=[malformed_name])
    failures2 = {f["FailureResource"]: f.get("FailureCode") for f in resp2["Failures"]}
    assert failures2 == {malformed_name: "INVALID_RULE_NAME"}, (
        f"expected the malformed name refused in Failures[] with INVALID_RULE_NAME, "
        f"got Failures={resp2['Failures']!r}"
    )


def _safe_delete_rules(ctx: Any, names: list[str]) -> None:
    cw = ctx.client("cloudwatch")
    cw.delete_insight_rules(RuleNames=names)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
