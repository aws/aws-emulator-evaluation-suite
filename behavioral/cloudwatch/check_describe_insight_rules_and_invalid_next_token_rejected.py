"""describe-insight-rules-and-invalid-next-token-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "describe-insight-rules-and-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DescribeInsightRules lists a freshly created rule with State ENABLED, and
    is rejected with InvalidNextToken for a garbage pagination token."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_definition = json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Filters": [], "Keys": ["$.ip"]},
            "LogFormat": "JSON",
            "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-")],
        }
    )
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=rule_definition)
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    found = _find_rule(ctx, rule_name)
    assert found is not None, f"{rule_name} should be listed by DescribeInsightRules"
    assert found["State"] == "ENABLED", f"newly created rule should default to ENABLED, got {found['State']!r}"
    found_log_format = json.loads(found["Definition"])["LogFormat"]
    assert found_log_format == "JSON", f"expected the rule's own Definition.LogFormat to read back as 'JSON', got {found_log_format!r}"

    # Error boundary: a stale/garbage NextToken is rejected outright.
    code, message = _client_error(lambda: cw.describe_insight_rules(NextToken="garbage-not-a-real-token"))
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code!r}"
    expected_message = "INVALID_TOKEN: Unsupported token version."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _find_rule(ctx: Any, rule_name: str, max_pages: int = 5):
    cw = ctx.client("cloudwatch")
    next_token = None
    for _ in range(max_pages):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cw.describe_insight_rules(**kwargs)
        for rule in resp["InsightRules"]:
            if rule["Name"] == rule_name:
                return rule
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return None


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a garbage NextToken real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
