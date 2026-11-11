"""delete-insight-rules-missing-required-parameter-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-insight-rules-missing-required-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules with an empty RuleNames list fails with InvalidParameterValue
    "EMPTY_RULE_NAMES: RuleNames cannot be an empty array."; a real rule name deletes it."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-cw-rule-")
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-behav-cw-lg-")],
        }
    )
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=rule_definition,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_rules(cw, [rule_name]))

    # Positive control: the account/credentials are otherwise healthy for
    # DeleteInsightRules -- a real name is accepted and the rule is actually
    # removed -- so the rejection below is attributable to the empty list, not
    # to every DeleteInsightRules call being refused.
    cw.delete_insight_rules(RuleNames=[rule_name])
    remaining = {r["Name"] for r in cw.describe_insight_rules()["InsightRules"]}
    assert rule_name not in remaining, "positive control: the real rule was not deleted"

    code, message = _error(lambda: cw.delete_insight_rules(RuleNames=[]))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected_message = "EMPTY_RULE_NAMES: RuleNames cannot be an empty array."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe_delete_rules(cw, names):
    cw.delete_insight_rules(RuleNames=names)


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected DeleteInsightRules(RuleNames=[]) to raise, but it succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
