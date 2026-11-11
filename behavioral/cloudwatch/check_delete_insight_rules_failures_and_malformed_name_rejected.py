"""delete-insight-rules-failures-and-malformed-name-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "delete-insight-rules-failures-and-malformed-name-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules on a real and a nonexistent rule name succeeds, removes the real rule and
    reports at most the missing name; a malformed name alone yields one Failures[] entry
    (InvalidParameterException, INVALID_RULE_NAME, quoting the name pattern) and no rule."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    missing_name = ctx.unique_name("sim2real-behav-rule-missing-")
    malformed_name = "bad rule name"
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-")],
        }
    )
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=rule_definition,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_rules(ctx, [rule_name]))

    # Success path: deleting a real rule together with a nonexistent name succeeds overall (no
    # exception) and the real rule is removed. Failures[] may be empty or name only the missing
    # rule; any other entry is an unrelated failure and fails the check.
    resp = cw.delete_insight_rules(RuleNames=[rule_name, missing_name])
    failures = {f["FailureResource"] for f in resp["Failures"]}
    assert failures in (set(), {missing_name}), (
        f"expected no failures or the nonexistent name as a failure, got {resp['Failures']!r}"
    )

    remaining_names = {r["Name"] for r in cw.describe_insight_rules()["InsightRules"]}
    assert rule_name not in remaining_names, "deleted rule must not be listed anymore"

    # Malformed-name rejection, tested in isolation: DeleteInsightRules refuses
    # a syntactically invalid name with its own per-item Failures[] entry
    # rather than treating it as a normal lookup-miss success.
    resp2 = cw.delete_insight_rules(RuleNames=[malformed_name])
    expected_failures = [
        {
            "FailureResource": malformed_name,
            "ExceptionType": "InvalidParameterException",
            "FailureCode": "INVALID_RULE_NAME",
            "FailureDescription": (
                f'RuleName "{malformed_name}" does not match the pattern: '
                "[A-Za-z0-9][A-Za-z0-9\\-\\_\\.]{0,126}[A-Za-z0-9]"
            ),
        }
    ]
    assert resp2["Failures"] == expected_failures, (
        f"expected Failures {expected_failures!r}, got {resp2['Failures']!r}"
    )

    remaining_after_malformed = {r["Name"] for r in cw.describe_insight_rules()["InsightRules"]}
    assert malformed_name not in remaining_after_malformed, (
        "malformed rule name must never be created as a rule"
    )


def _safe_delete_rules(ctx: Any, names: list[str]) -> None:
    cw = ctx.client("cloudwatch")
    cw.delete_insight_rules(RuleNames=names)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
