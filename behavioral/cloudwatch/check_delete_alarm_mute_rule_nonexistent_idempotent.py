"""delete-alarm-mute-rule-nonexistent-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-alarm-mute-rule-nonexistent-idempotent"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlarmMuteRule on a nonexistent rule succeeds silently (idempotent delete),
    matching alarm delete semantics."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "delete_alarm_mute_rule"):
        raise AssertionError(
            "cloudwatch client lacks delete_alarm_mute_rule; botocore predates the AlarmMuteRule API"
        )

    name = ctx.unique_name("sim2real-mute-nonexistent-")

    # Confirm it really doesn't exist first.
    code, message = _refusal(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name))
    assert code == "ResourceNotFoundException", f"expected the probe rule to be absent, got {code} ({message!r})"
    # Real CloudWatch answers a missing mute rule with an EMPTY Error.Message.
    assert message == "", f"unexpected ResourceNotFoundException message {message!r}"

    resp = cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeleteAlarmMuteRule on a nonexistent rule to return 200, "
        f"got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    # The delete of a nonexistent rule must be a true no-op: the rule must still be
    # absent afterwards (not, say, materialized as a tombstone/placeholder record).
    code_after_first, message_after_first = _refusal(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    )
    assert code_after_first == "ResourceNotFoundException", (
        f"rule unexpectedly became visible after deleting a nonexistent rule, got {code_after_first}"
    )
    assert message_after_first == message, (
        f"unexpected ResourceNotFoundException message {message_after_first!r}"
    )
    # NOTE: ListAlarmMuteRules(AlarmName=...) validates that the named *alarm* exists
    # and raises ResourceNotFoundException if it doesn't -- it is not a simple filter
    # over mute rules. `name` here is a bogus alarm-mute-rule name, not a real alarm,
    # so it must not be passed as the AlarmName filter. List unfiltered instead, and
    # recover names from AlarmMuteRuleArn since AlarmMuteRuleSummary carries no "Name"
    # field.
    names_after_first = [
        _arn_name(s["AlarmMuteRuleArn"])
        for s in cw.list_alarm_mute_rules().get("AlarmMuteRuleSummaries", [])
    ]
    assert name not in names_after_first, f"{name} unexpectedly present in list_alarm_mute_rules"


    # Deleting the same still-nonexistent rule again must also succeed (idempotent) and
    # must leave the same absent state behind.
    resp2 = cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the second idempotent delete to also return 200, "
        f"got {resp2['ResponseMetadata']['HTTPStatusCode']}"
    )
    code_after_second, message_after_second = _refusal(
        lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name)
    )
    assert code_after_second == "ResourceNotFoundException", (
        f"rule unexpectedly became visible after a second idempotent delete, got {code_after_second}"
    )
    assert message_after_second == message, (
        f"unexpected ResourceNotFoundException message {message_after_second!r}"
    )


def _refusal(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the mute rule to be absent, but the read SUCCEEDED and returned {result!r}")


def _arn_name(arn: str) -> str:
    """Recover the resource name from an ARN whose final segment is the name,
    regardless of whether it's colon- or slash-delimited."""
    tail = arn.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
