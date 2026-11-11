"""get-insight-rule-report-nonexistent-rule-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-rule-report-nonexistent-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """GetInsightRuleReport on an existing rule returns KeyLabels ["$.ip"], while for a rule name
    that was never created it fails with InvalidParameterValue "RULE_NAME: <name>"."""
    cw = ctx.client("cloudwatch")

    live_rule_name = ctx.unique_name("sim2real-insight-rule-live-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-") + "*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=live_rule_name,
        RuleDefinition=json.dumps(rule_definition),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[live_rule_name]))

    end = int(time.time())
    start = end - 3600

    positive = cw.get_insight_rule_report(RuleName=live_rule_name, StartTime=start, EndTime=end, Period=60)
    assert positive.get("KeyLabels") == ["$.ip"], f"expected KeyLabels echoing the rule definition, got {positive!r}"

    missing_rule_name = ctx.unique_name("sim2real-insight-rule-missing-")
    code, message = _error_code(
        lambda: cw.get_insight_rule_report(
            RuleName=missing_rule_name,
            StartTime=start,
            EndTime=end,
            Period=60,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = f"RULE_NAME: {missing_rule_name}"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so an
    emulator accepting a rule name AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected GetInsightRuleReport to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
