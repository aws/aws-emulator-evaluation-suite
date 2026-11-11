"""enable-insight-rules-and-malformed-name-reported-as-failure-entry."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "enable-insight-rules-and-malformed-name-reported-as-failure-entry"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """EnableInsightRules re-enables a disabled rule and reports a missing name (RULE_NAME) and a
    malformed name (INVALID_RULE_NAME) as distinct per-item Failures entries instead of raising.
    """
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    missing_name = ctx.unique_name("sim2real-behav-rule-missing-")
    malformed_name = "\x01bad-rule"
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
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))
    cw.disable_insight_rules(RuleNames=[rule_name])
    disabled_state = _rule_state(ctx, rule_name)
    assert disabled_state == "DISABLED", f"expected DISABLED after disable, got {disabled_state!r}"

    resp = cw.enable_insight_rules(RuleNames=[rule_name, missing_name, malformed_name])
    by_resource = {f["FailureResource"]: f for f in resp["Failures"]}
    assert by_resource.keys() == {missing_name, malformed_name}, (
        f"expected both the nonexistent and malformed names as failures, got {resp['Failures']!r}"
    )

    missing_failure = by_resource[missing_name]
    assert missing_failure.get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the missing rule name, got {missing_failure!r}"
    )
    assert missing_failure.get("FailureCode") == "RULE_NAME", (
        f"expected FailureCode RULE_NAME for the missing rule name, got {missing_failure!r}"
    )

    malformed_failure = by_resource[malformed_name]
    assert malformed_failure.get("ExceptionType") == "InvalidParameterException", (
        f"expected InvalidParameterException for the malformed rule name, got {malformed_failure!r}"
    )
    assert malformed_failure.get("FailureCode") == "INVALID_RULE_NAME", (
        f"expected FailureCode INVALID_RULE_NAME for the malformed rule name, got {malformed_failure!r}"
    )
    assert missing_failure["ExceptionType"] != malformed_failure["ExceptionType"], (
        "the missing-rule and malformed-name failures must be independently classified, "
        f"got the same ExceptionType for both: {resp['Failures']!r}"
    )

    state = _rule_state(ctx, rule_name)
    assert state == "ENABLED", f"expected ENABLED, got {state!r}"


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
