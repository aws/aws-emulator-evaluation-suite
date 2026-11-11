"""get-insight-rule-report-missing-required-param."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-rule-report-missing-required-param"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """GetInsightRuleReport without Period, sent past client-side validation, fails with
    MissingParameter "MISSING_PERIOD: The Period parameter must be present in a GetContributors
    request."; with Period the same call returns KeyLabels ["$.ip"]."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-insight-missing-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [ctx.unique_name("sim2real-behav-lg-") + "*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=json.dumps(rule_definition),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)

    # A rule with no matching log events yet has nothing to report, so CloudWatch omits
    # MetricDatapoints/Timestamps entirely rather than returning them empty; KeyLabels (echoing
    # the Contribution.Keys from the rule definition above) is the field asserted instead.
    report = cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=now, Period=60)
    assert report.get("KeyLabels") == ["$.ip"], f"expected KeyLabels echoing the rule definition, got {report!r}"

    # Period is intentionally omitted below. boto3 would normally refuse to even build the
    # request locally, so a client built with Config(parameter_validation=False) lets the
    # incomplete request reach the service and exercise its own validation.
    no_validate = ctx.client("cloudwatch", config=Config(parameter_validation=False))
    code, message = _error(
        lambda: no_validate.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=now)
    )
    assert code == "MissingParameter", f"expected MissingParameter, got {code}"
    assert message == (
        "MISSING_PERIOD: The Period parameter must be present in a GetContributors request."
    ), f"unexpected MissingParameter message {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so an over-permissive target's acceptance is never reported as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
