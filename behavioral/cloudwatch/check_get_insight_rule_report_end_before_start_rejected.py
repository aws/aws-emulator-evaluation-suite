"""get-insight-rule-report-end-before-start-rejected."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-rule-report-end-before-start-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """GetInsightRuleReport rejects a time range where EndTime is before StartTime. A positive
    control on the identical rule with a validly-ordered range proves the rejection is specific to
    the reversed range, not the rule or the account."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-badrange-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-") + "*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=json.dumps(rule_definition))
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    now = datetime.now(timezone.utc)

    control = cw.get_insight_rule_report(
        RuleName=rule_name,
        StartTime=now - timedelta(hours=1),
        EndTime=now,
        Period=60,
    )
    assert "KeyLabels" in control, (
        f"positive control: expected a well-formed report for a validly-ordered range, got {control}"
    )

    code, message = _error(
        lambda: cw.get_insight_rule_report(
            RuleName=rule_name,
            StartTime=now,
            EndTime=now - timedelta(hours=1),
            Period=60,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for EndTime before StartTime, got {code}"
    assert message == "INVALID_TIME_RANGE: The StartTime must precede the EndTime.", f"unexpected InvalidParameterValue message {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection for EndTime before StartTime, but call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
