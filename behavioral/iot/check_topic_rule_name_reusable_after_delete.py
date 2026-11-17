"""topic-rule-name-reusable-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-rule-name-reusable-after-delete"
GROUP = "topic-rule"
SERVICES = ["iot"]


def _rule_action(function_arn: str) -> dict:
    """A lambda action names no role, so CreateTopicRule never checks the function exists."""
    return {"lambda": {"functionArn": function_arn}}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A topic rule's name frees on delete: a live rule keeps its SQL through a rejected
    duplicate create, GetTopicRule on the deleted rule fails, and the freed name's next
    CreateTopicRule carries the new SQL."""
    iot = ctx.client("iot")
    function_arn = (
        f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:"
        f"{ctx.unique_name('sim2real-behav-reuse-fn-')}"
    )
    rule_name = ctx.unique_name("sim2real_behav_reuse_rule_").replace("-", "_")
    first_sql = "SELECT * FROM 'sim2real/behav/reuse/first'"
    second_sql = "SELECT * FROM 'sim2real/behav/reuse/second'"

    def _create(sql: str) -> None:
        iot.create_topic_rule(
            ruleName=rule_name,
            topicRulePayload={"sql": sql, "actions": [_rule_action(function_arn)]},
        )

    _create(first_sql)
    ctx.on_cleanup(
        _teardown(lambda: iot.delete_topic_rule(ruleName=rule_name), "UnauthorizedException")
    )

    code, message = _err(lambda: _create(second_sql))
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException for the conflicting re-create, got {code!r}"
    )
    expected_conflict = f"Topic Rule '{rule_name}' already exists for account"
    assert message == expected_conflict, f"expected {expected_conflict!r}, got {message!r}"

    live = iot.get_topic_rule(ruleName=rule_name)["rule"]
    assert live["sql"] == first_sql, (
        f"expected the rejected create to leave {first_sql!r} in place, got {live['sql']!r}"
    )

    iot.delete_topic_rule(ruleName=rule_name)

    code2, message2 = _err(lambda: iot.get_topic_rule(ruleName=rule_name))
    assert code2 == "UnauthorizedException", (
        f"expected UnauthorizedException reading the deleted rule, got {code2!r}"
    )
    expected_gone = f"Access to topic rule '{rule_name}' was denied"
    assert message2 == expected_gone, f"expected {expected_gone!r}, got {message2!r}"

    _create(second_sql)
    ctx.on_cleanup(
        _teardown(lambda: iot.delete_topic_rule(ruleName=rule_name), "UnauthorizedException")
    )

    restored = iot.get_topic_rule(ruleName=rule_name)["rule"]
    assert restored["sql"] == second_sql, (
        f"expected {second_sql!r} after re-create under the freed name, got {restored['sql']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
