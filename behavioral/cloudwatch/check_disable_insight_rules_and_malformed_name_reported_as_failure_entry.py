"""disable-insight-rules-and-malformed-name-reported-as-failure-entry."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "disable-insight-rules-and-malformed-name-reported-as-failure-entry"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DisableInsightRules on a real, a nonexistent and a malformed rule name succeeds, reports the
    two bad names in Failures[] as ResourceNotFoundException and InvalidParameterException, and sets
    the real rule's State to DISABLED."""
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

    # Success path + per-item failure semantics: disabling a real rule together with a
    # nonexistent and a malformed name succeeds overall; the nonexistent name is a lookup miss
    # (ResourceNotFoundException), the malformed one a rejected pattern (InvalidParameterException).
    resp = cw.disable_insight_rules(RuleNames=[rule_name, missing_name, malformed_name])
    failures = {f["FailureResource"]: f for f in resp["Failures"]}
    assert set(failures) == {missing_name, malformed_name}, (
        f"expected both the nonexistent and malformed names as failures, got {resp['Failures']!r}"
    )
    assert failures[missing_name]["ExceptionType"] == "ResourceNotFoundException", (
        f"expected the nonexistent rule name to be classified as ResourceNotFoundException, "
        f"got {failures[missing_name]!r}"
    )
    assert failures[malformed_name]["ExceptionType"] == "InvalidParameterException", (
        f"expected the malformed rule name to be classified as InvalidParameterException "
        f"(distinct from the nonexistent name's ResourceNotFoundException), "
        f"got {failures[malformed_name]!r}"
    )

    state = _rule_state(ctx, rule_name)
    assert state == "DISABLED", f"expected DISABLED, got {state!r}"


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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
