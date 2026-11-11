"""put-insight-rule-invalid-definition-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-insight-rule-invalid-definition-rejected"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """PutInsightRule rejects a RuleDefinition that fails schema validation (missing
    the required LogGroupNames/Contribution fields) with InvalidParameterValueException,
    the rule is never created, and a syntactically valid definition still succeeds."""
    cw = ctx.client("cloudwatch")

    bad_rule_name = ctx.unique_name("sim2real-cw-insight-bad-")
    # Missing LogGroupNames, LogFormat, Contribution, and AggregateOn -- fails schema
    # validation.
    bad_definition = json.dumps({"Schema": {"Name": "CloudWatchLogRule", "Version": 1}})

    error = _client_error(
        lambda: cw.put_insight_rule(RuleName=bad_rule_name, RuleDefinition=bad_definition)
    )
    assert error.get("Code") == "InvalidParameterValue", f"unexpected error: {error!r}"
    assert error.get("Message") == "INVALID_RULE_BODY: MissingKey encountered at Contribution in the RuleBody.", (
        f"unexpected message for an invalid RuleDefinition: {error.get('Message')!r}"
    )

    existing_names = {r["Name"] for r in _list_all_insight_rules(ctx)}
    assert bad_rule_name not in existing_names, (
        "rule with an invalid definition should not have been created"
    )

    good_rule_name = ctx.unique_name("sim2real-cw-insight-good-")
    log_group_name = ctx.unique_name("/sim2real/cw-insight-neg-")
    good_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "LogGroupNames": [log_group_name],
            "LogFormat": "JSON",
            "Contribution": {"Keys": ["$.user"], "Filters": []},
            "AggregateOn": "Count",
        }
    )
    cw.put_insight_rule(
        RuleName=good_rule_name,
        RuleDefinition=good_definition,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[good_rule_name]))

    existing_names_after = {r["Name"] for r in _list_all_insight_rules(ctx)}
    assert good_rule_name in existing_names_after, (
        "a syntactically valid rule definition should have been created"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


def _list_all_insight_rules(ctx) -> list:
    cw = ctx.client("cloudwatch")
    rules = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cw.describe_insight_rules(**kwargs)
        rules.extend(resp.get("InsightRules", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return rules


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
