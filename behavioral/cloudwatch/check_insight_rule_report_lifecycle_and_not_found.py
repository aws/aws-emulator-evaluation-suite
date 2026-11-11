"""insight-rule-report-lifecycle-and-not-found."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "insight-rule-report-lifecycle-and-not-found"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """GetInsightRuleReport succeeds for a rule created by PutInsightRule and, once DeleteInsightRules
    removes it, fails with InvalidParameterValue (RULE_NAME: <name>): a deleted rule is rejected
    like an unknown name, with no dedicated not-found error."""
    cw = ctx.client("cloudwatch")

    rule_name = ctx.unique_name("sim2real-insight-rule-")
    log_group_name = ctx.unique_name("/sim2real/insight-rule-source-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [log_group_name],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.clientIp"], "Filters": []},
        "AggregateOn": "Count",
    }
    import json as _json

    put_resp = cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=_json.dumps(rule_definition),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    assert put_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected PutInsightRule to succeed with HTTP 200, got {put_resp['ResponseMetadata']}"
    )

    def _cleanup_rule():
        # DeleteInsightRules succeeds with empty Failures for a missing rule, so any error raises.
        failures = cw.delete_insight_rules(RuleNames=[rule_name]).get("Failures", [])
        if failures:
            raise AssertionError(f"DeleteInsightRules left {rule_name} behind: {failures}")

    ctx.on_cleanup(_cleanup_rule)

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=10)
    report = cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=end, Period=60)
    assert "Contributors" in report, f"expected a Contributors field in the report, got keys {sorted(report)}"
    assert "KeyLabels" in report and len(report["KeyLabels"]) == 1, (
        f"expected exactly 1 KeyLabels entry (one Contribution.Keys entry was configured), got {report.get('KeyLabels')}"
    )

    delete_resp = cw.delete_insight_rules(RuleNames=[rule_name])
    assert delete_resp.get("Failures", []) == [], f"unexpected delete failures: {delete_resp.get('Failures')}"

    # The delete propagates to GetInsightRuleReport eventually, so poll (bounded) for the refusal.
    code, message = _poll_error(
        lambda: cw.get_insight_rule_report(RuleName=rule_name, StartTime=start, EndTime=end, Period=60)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue after delete, got {code}"
    assert message == f"RULE_NAME: {rule_name}", f"unexpected message after delete: {message!r}"


# ===== helpers =====
def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_error(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """_error(fn) once fn() is refused; raises if it still succeeds when the timeout elapses."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
