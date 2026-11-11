"""replace-topic-rule-replaces-not-merges."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "replace-topic-rule-replaces-not-merges"
GROUP = 'topic-rule'
SERVICES = ['iot']


def _rule_action(probe_lambda_arn: str) -> dict:
    """A topic-rule action that requires no IAM role (avoids iam:PassRole)."""
    return {"lambda": {"functionArn": probe_lambda_arn}}


def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    AWS IoT propagates writes asynchronously, so early reads can raise ResourceNotFoundException.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceTopicRule replaces rather than merges: omitted description, surplus action and
    errorAction are dropped, sql/awsIotSqlVersion/ruleDisabled come from the new payload, and
    ListTopicRules holds the rule once."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    # fabricated function ARNs: CreateTopicRule validates the ARN's shape, not its existence
    action_a = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-probe-fn"
    action_b = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-probe-fn-2"
    rule_name = ctx.unique_name("sim2real-behav-rule_replace_").replace("-", "_")

    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": "SELECT * FROM 'sim2real/behav/replace/before'",
            "description": "sim2real-behav original description",
            "actions": [_rule_action(action_a), _rule_action(action_b)],
            "ruleDisabled": False,
            "awsIotSqlVersion": "2016-03-23",
            "errorAction": _rule_action(action_b),
        },
    )
    ctx.on_cleanup(lambda _n=rule_name: iot.delete_topic_rule(ruleName=_n))

    before = _eventually(
        lambda: iot.get_topic_rule(ruleName=rule_name)["rule"],
        lambda r: r.get("description") == "sim2real-behav original description",
        timeout_s=60,
    )
    assert len(before["actions"]) == 2, f"setup: expected 2 actions, got {before['actions']}"
    assert before.get("errorAction"), "setup: errorAction must be present before the replace"

    new_sql = "SELECT temperature FROM 'sim2real/behav/replace/after'"
    iot.replace_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": new_sql,
            "actions": [_rule_action(action_a)],
            "ruleDisabled": True,
            "awsIotSqlVersion": "2015-10-08",
        },
    )

    after = _eventually(
        lambda: iot.get_topic_rule(ruleName=rule_name)["rule"],
        lambda r: r.get("sql") == new_sql,
        timeout_s=60,
    )
    assert after["sql"] == new_sql, f"sql must come from the new payload, got {after['sql']!r}"
    assert after["awsIotSqlVersion"] == "2015-10-08", (
        f"awsIotSqlVersion must come from the new payload, got {after['awsIotSqlVersion']!r}"
    )
    assert after["ruleDisabled"] is True, f"ruleDisabled must be True after replace, got {after['ruleDisabled']!r}"
    assert not after.get("description"), (
        f"a description omitted from the replacement payload must be DROPPED, got {after.get('description')!r}"
    )
    assert len(after["actions"]) == 1, (
        f"the surplus action must be dropped, not merged; got {len(after['actions'])} actions: {after['actions']}"
    )
    assert after["actions"][0]["lambda"]["functionArn"] == action_a, (
        f"the surviving action must be the one in the replacement payload, got {after['actions'][0]}"
    )
    assert not after.get("errorAction"), (
        f"an errorAction omitted from the replacement payload must be DROPPED, got {after.get('errorAction')!r}"
    )

    pages = iot.get_paginator("list_topic_rules").paginate()
    matches = [r for page in pages for r in page["rules"] if r["ruleName"] == rule_name]
    assert len(matches) == 1, f"replace must not duplicate the rule; ListTopicRules returned {matches}"
    assert matches[0].get("ruleDisabled") is True, (
        f"ListTopicRules must reflect the replaced ruleDisabled flag, got {matches[0]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
