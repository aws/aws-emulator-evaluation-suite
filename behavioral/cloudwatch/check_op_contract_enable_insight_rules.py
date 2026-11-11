"""op-contract-enableInsightRules."""
from __future__ import annotations

import json
import time

from botocore.config import Config

from behavioral_harness import tags

CHECK = "op-contract-enableInsightRules"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """EnableInsightRules moves a DISABLED rule to ENABLED and reports, without raising, a nonexistent name
    as a ResourceNotFoundException Failures entry ("Rule <name> does not exist.") and an empty name as
    InvalidParameterException "RuleName cannot be an empty string."."""
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
        RuleState="DISABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    disabled_state = _poll_until(
        lambda: _rule_state(cw, rule_name), lambda s: s == "DISABLED", timeout_s=20
    )
    assert disabled_state == "DISABLED", f"expected DISABLED, got {disabled_state!r}"

    missing_rule = ctx.unique_name("sim2real-cw-missing-rule-")
    resp = cw.enable_insight_rules(RuleNames=[rule_name, missing_rule])
    assert len(resp["Failures"]) == 1, f"expected exactly 1 failure entry, got {resp['Failures']!r}"
    failure = resp["Failures"][0]
    assert failure["FailureResource"] == missing_rule, (
        f"expected the failure entry to name {missing_rule!r}, got {failure!r}"
    )
    assert failure["ExceptionType"] == "ResourceNotFoundException", (
        f"expected a well-formed but nonexistent rule name to be classified as "
        f"ResourceNotFoundException, got {failure!r}"
    )
    expected = f"Rule {missing_rule} does not exist."
    assert failure["FailureDescription"] == expected, (
        f"expected FailureDescription {expected!r}, got {failure!r}"
    )

    enabled_state = _poll_until(
        lambda: _rule_state(cw, rule_name), lambda s: s == "ENABLED", timeout_s=20
    )
    assert enabled_state == "ENABLED", (
        "the valid rule in the batch must transition to ENABLED despite the sibling failure"
    )

    # botocore rejects an empty RuleName locally (modelled minLength 1), so client-side validation
    # is off here to let the empty name reach the service, which answers 200 with a Failures entry.
    unvalidated_cw = ctx.client("cloudwatch", config=Config(parameter_validation=False))
    resp = unvalidated_cw.enable_insight_rules(RuleNames=[""])
    empty_failures = {f["FailureResource"]: f for f in resp["Failures"]}
    assert "" in empty_failures, (
        f"expected the empty-string rule name to be reported as a soft Failures[] entry "
        f"(the same non-raising path as an unknown name), got {resp['Failures']!r}"
    )
    assert empty_failures[""]["ExceptionType"] == "InvalidParameterException", (
        f"expected the empty-string rule name to be classified as InvalidParameterException "
        f"(distinct from a nonexistent name's ResourceNotFoundException), got {empty_failures['']!r}"
    )
    assert empty_failures[""]["FailureDescription"] == "RuleName cannot be an empty string.", (
        f"expected FailureDescription 'RuleName cannot be an empty string.', got {empty_failures['']!r}"
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
            raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
