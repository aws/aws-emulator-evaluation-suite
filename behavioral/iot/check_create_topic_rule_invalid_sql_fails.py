"""create-topic-rule-invalid-sql-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-topic-rule-invalid-sql-fails"
GROUP = 'topic-rule'
SERVICES = ['iot']

def _rule_action(probe_lambda_arn: str) -> dict:
    """A topic-rule action that requires no IAM role (avoids iam:PassRole)."""
    return {"lambda": {"functionArn": probe_lambda_arn}}

def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopicRule with a malformed SQL statement must be rejected, not silently accepted —
    while a syntactically valid rule of the same shape, against the same account, still creates
    successfully (positive control)."""
    iot = ctx.client("iot")
    _acct = ctx.client("sts").get_caller_identity()["Account"]
    probe_lambda_arn = f"arn:aws:lambda:{ctx.region}:{_acct}:function:sim2real-behav-probe-fn"

    # positive control: a syntactically valid rule with the same shape succeeds, so the
    # negative below cannot be "rejects every CreateTopicRule" in disguise.
    good_rule_name = ctx.unique_name("sim2real-behav-rule_good_sql_").replace("-", "_")
    iot.create_topic_rule(
        ruleName=good_rule_name,
        topicRulePayload={
            "sql": "SELECT * FROM 'sim2real/behav/probe/good'",
            "actions": [_rule_action(probe_lambda_arn)],
        },
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=good_rule_name))
    fetched = iot.get_topic_rule(ruleName=good_rule_name)
    assert fetched["rule"]["ruleName"] == good_rule_name, (
        f"expected the positive-control rule {good_rule_name!r} to read back, got {fetched.get('rule')}"
    )

    rule_name = ctx.unique_name("sim2real-behav-rule_bad_sql_").replace("-", "_")
    err = _error(
        lambda: iot.create_topic_rule(
            ruleName=rule_name,
            topicRulePayload={
                "sql": "THIS IS NOT VALID IOT SQL ((((",
                "actions": [_rule_action(probe_lambda_arn)],
            },
        )
    )
    assert err == ("SqlParseException", "Expected 'SELECT'\n\nTHIS IS NOT VALID IOT SQL ((((\n^ at 1:1"), err

    # the rule must not exist
    not_found = _error(lambda: iot.get_topic_rule(ruleName=rule_name))
    assert not_found == ("UnauthorizedException", f"Access to topic rule '{rule_name}' was denied"), (
        f"expected the never-created rule {rule_name!r} to read back not-found, got {not_found!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
