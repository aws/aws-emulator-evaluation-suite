"""op-contract-disableInsightRules."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-disableInsightRules"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DisableInsightRules reports an unknown rule name (ResourceNotFoundException, RULE_NAME) and a
    pattern-violating one (InvalidParameterException, INVALID_RULE_NAME) as Failures entries with their
    exact descriptions, without raising, while the valid rule in the batch moves to DISABLED."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-cw-rule-")
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-cw-loggroup-")],
        }
    )
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=rule_definition,
        RuleState="ENABLED",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    enabled_state = _poll_until(
        lambda: _rule_state(cw, rule_name), lambda s: s == "ENABLED", timeout_s=20
    )
    assert enabled_state == "ENABLED", f"expected the freshly-created rule ENABLED, got {enabled_state!r}"

    missing_rule = ctx.unique_name("sim2real-cw-missing-rule-")
    resp = cw.disable_insight_rules(RuleNames=[rule_name, missing_rule])
    assert len(resp["Failures"]) == 1, f"expected exactly 1 failure entry, got {resp['Failures']!r}"
    failure = resp["Failures"][0]
    assert failure["FailureResource"] == missing_rule, (
        f"expected the failure to name {missing_rule!r}, got {failure['FailureResource']!r}"
    )
    assert failure["ExceptionType"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown rule name, got {failure['ExceptionType']!r}"
    )
    assert failure["FailureCode"] == "RULE_NAME", (
        f"expected FailureCode RULE_NAME for an unknown rule name, got {failure['FailureCode']!r}"
    )
    expected = f"Rule {missing_rule} does not exist."
    assert failure["FailureDescription"] == expected, (
        f"expected FailureDescription {expected!r}, got {failure.get('FailureDescription')!r}"
    )

    # A name violating the naming pattern is a different soft failure than "does not exist":
    # AWS answers 200 with a Failures entry, not an error.
    invalid_rule_name = "sim2real!invalid"
    invalid_resp = cw.disable_insight_rules(RuleNames=[invalid_rule_name])
    assert len(invalid_resp["Failures"]) == 1, (
        f"expected exactly 1 failure entry for a malformed name, got {invalid_resp['Failures']!r}"
    )
    invalid_failure = invalid_resp["Failures"][0]
    assert invalid_failure["FailureResource"] == invalid_rule_name, (
        f"expected the failure to name {invalid_rule_name!r}, got {invalid_failure['FailureResource']!r}"
    )
    assert invalid_failure["ExceptionType"] == "InvalidParameterException", (
        "expected InvalidParameterException for a pattern-violating rule name, got "
        f"{invalid_failure['ExceptionType']!r}"
    )
    assert invalid_failure["FailureCode"] == "INVALID_RULE_NAME", (
        "expected FailureCode INVALID_RULE_NAME (distinct from the not-found case's RULE_NAME), got "
        f"{invalid_failure['FailureCode']!r}"
    )
    expected_invalid = (
        f'RuleName "{invalid_rule_name}" does not match the pattern: '
        r"[A-Za-z0-9][A-Za-z0-9\-\_\.]{0,126}[A-Za-z0-9]"
    )
    assert invalid_failure["FailureDescription"] == expected_invalid, (
        f"expected FailureDescription {expected_invalid!r}, got "
        f"{invalid_failure.get('FailureDescription')!r}"
    )

    disabled_state = _poll_until(
        lambda: _rule_state(cw, rule_name), lambda s: s == "DISABLED", timeout_s=20
    )
    assert disabled_state == "DISABLED", (
        "the valid rule in the batch must transition to DISABLED despite the sibling failures, "
        f"got {disabled_state!r}"
    )


def _rule_state(cw, rule_name: str) -> str:
    for rule in cw.describe_insight_rules()["InsightRules"]:
        if rule["Name"] == rule_name:
            return rule["State"]
    raise AssertionError(f"rule {rule_name} disappeared")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for the predicate; last value {result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
