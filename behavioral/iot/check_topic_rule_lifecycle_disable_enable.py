"""topic-rule-lifecycle-disable-enable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-rule-lifecycle-disable-enable"
GROUP = 'topic-rule'
SERVICES = ['iot']

def _rule_action(probe_lambda_arn: str) -> dict:
    """A topic-rule action that requires no IAM role (avoids iam:PassRole)."""
    return {"lambda": {"functionArn": probe_lambda_arn}}

def _err(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Topic rule: create enabled -> GetTopicRule reflects it -> disable via ReplaceTopicRule ->
    re-enable via ReplaceTopicRule -> delete -> GetTopicRule fails."""
    iot = ctx.client("iot")
    _acct = ctx.client("sts").get_caller_identity()["Account"]
    probe_lambda_arn = f"arn:aws:lambda:{ctx.region}:{_acct}:function:sim2real-behav-probe-fn"
    rule_name = ctx.unique_name("sim2real-behav-rule_").replace("-", "_")
    sql = "SELECT * FROM 'behavioral/probe/topic'"
    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": sql,
            "actions": [_rule_action(probe_lambda_arn)],
            "ruleDisabled": False,
        },
    )
    ctx.on_cleanup(lambda _n=rule_name: iot.delete_topic_rule(ruleName=_n))

    got = iot.get_topic_rule(ruleName=rule_name)
    assert got["rule"]["sql"] == sql, f"expected sql {sql!r}, got {got['rule']['sql']!r}"
    assert got["rule"]["ruleDisabled"] is False, (
        f"expected ruleDisabled False on create, got {got['rule']['ruleDisabled']!r}"
    )

    iot.replace_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": sql,
            "actions": [_rule_action(probe_lambda_arn)],
            "ruleDisabled": True,
        },
    )
    got_after = iot.get_topic_rule(ruleName=rule_name)
    assert got_after["rule"]["ruleDisabled"] is True, (
        f"expected ruleDisabled True after disabling ReplaceTopicRule, got {got_after['rule']['ruleDisabled']!r}"
    )

    iot.replace_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": sql,
            "actions": [_rule_action(probe_lambda_arn)],
            "ruleDisabled": False,
        },
    )
    got_reenabled = iot.get_topic_rule(ruleName=rule_name)
    assert got_reenabled["rule"]["ruleDisabled"] is False, (
        f"expected ruleDisabled False after re-enabling ReplaceTopicRule, got {got_reenabled['rule']['ruleDisabled']!r}"
    )

    iot.delete_topic_rule(ruleName=rule_name)
    code, message = _err(lambda: iot.get_topic_rule(ruleName=rule_name))
    assert code == "UnauthorizedException", (
        f"expected UnauthorizedException after delete, got {code!r}"
    )
    assert message == f"Access to topic rule '{rule_name}' was denied", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
