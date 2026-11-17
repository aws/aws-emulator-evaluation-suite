"""put-rule-refuses-a-numeric-operand-no-double-represents-and-keeps-the-stored-pattern."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-refuses-a-numeric-operand-no-double-represents-and-keeps-the-stored-pattern"
GROUP = 'event-pattern-language'
SERVICES = ['events']

# The operand sits between these two literals, so the column the refusal reports is derivable.
_HEAD = '{"detail": {"n": [{"numeric": ["=", '
_TAIL = ']}]}}'


def _pattern(operand: int) -> str:
    return f"{_HEAD}{operand}{_TAIL}"


def _refusal_column(operand: int) -> int:
    """The 1-based column of the brace closing the matcher object that holds ``operand``."""
    return len(_HEAD) + len(str(operand)) + len("]}")


def _representable(operand: int) -> bool:
    """Whether ``operand`` survives a round trip through an IEEE 754 binary64 double."""
    return int(float(operand)) == operand


def _refusal(fn):
    """The (Code, Message) pair ``fn`` is refused with; an unexpected success raises."""
    try:
        outcome = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {outcome!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where only the named not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c7", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A numeric operand no binary64 double represents exactly is refused by PutRule, which leaves
    the rule's stored pattern and the pattern's verdicts untouched and mints no rule for a new name.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
    """
    ev = ctx.client("events")

    # Above 2**53 a double carries only the even integers, so these two differ by one and only one
    # of them survives the round trip.
    accepted = 2 ** 53 + 2
    refused = 2 ** 53 + 1
    assert _representable(accepted) and not _representable(refused), (
        f"derivation error: {accepted} must be an exact double and {refused} must not be, "
        f"but round trips gave {int(float(accepted))} and {int(float(refused))}"
    )

    rule = ctx.unique_name("sim2real-numop-")
    ev.put_rule(
        Name=rule, EventPattern=_pattern(accepted), State="ENABLED",
        Description="sim2real numeric operand precision",
        Tags=[{"Key": "sim2real", "Value": "numeric-operand-precision"}],
    )
    ctx.on_cleanup(_teardown(lambda: ev.delete_rule(Name=rule, Force=True),
                             "ResourceNotFoundException"))

    stored = ev.describe_rule(Name=rule)["EventPattern"]
    assert stored == _pattern(accepted), (
        f"PutRule stored {stored!r} for the exactly-representable operand, "
        f"expected {_pattern(accepted)!r}"
    )

    # Breaking only the operand's representability must refuse the otherwise identical update.
    code, message = _refusal(
        lambda: ev.put_rule(Name=rule, EventPattern=_pattern(refused), State="ENABLED")
    )
    assert code == "InvalidEventPatternException", (
        f"an operand no double represents gave {code!r}, expected InvalidEventPatternException"
    )
    expected = (
        f"Event pattern is not valid. Reason: Cannot compare number : {refused}\n"
        f' at [Source: (String)"{_pattern(refused)}"; line: 1, column: {_refusal_column(refused)}]'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The refused update must not have replaced what the rule already carried.
    after = ev.describe_rule(Name=rule)["EventPattern"]
    assert after == _pattern(accepted), (
        f"the refused update left the rule holding {after!r}, expected {_pattern(accepted)!r}"
    )
    assert ev.test_event_pattern(EventPattern=after, Event=_event(ctx, accepted))["Result"] is True, (
        f"the surviving pattern stopped matching the operand {accepted} it compares against"
    )

    # Nor may the refusal leave a rule behind under a name that never held one.
    fresh = ctx.unique_name("sim2real-numop-new-")
    code2, message2 = _refusal(
        lambda: ev.put_rule(Name=fresh, EventPattern=_pattern(refused), State="ENABLED")
    )
    assert code2 == "InvalidEventPatternException", (
        f"creating a rule with that operand gave {code2!r}, expected InvalidEventPatternException"
    )
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"
    minted = set()
    for page in ev.get_paginator("list_rules").paginate(NamePrefix=fresh):
        minted |= {r["Name"] for r in page["Rules"]}
    assert minted == set(), f"the refused create still minted rule(s) {sorted(minted)!r}"

    # The legal neighbour of the refused input is accepted on the same name, so the refusal is
    # pinned to the operand's representability and not to the operand's magnitude.
    ev.put_rule(Name=fresh, EventPattern=_pattern(accepted), State="ENABLED",
                Description="sim2real numeric operand precision",
                Tags=[{"Key": "sim2real", "Value": "numeric-operand-precision"}])
    ctx.on_cleanup(_teardown(lambda: ev.delete_rule(Name=fresh, Force=True),
                             "ResourceNotFoundException"))
    neighbour = ev.describe_rule(Name=fresh)["EventPattern"]
    assert neighbour == _pattern(accepted), (
        f"the neighbouring operand stored {neighbour!r}, expected {_pattern(accepted)!r}"
    )


def _event(ctx, value: int) -> str:
    """A complete EventBridge envelope whose `detail.n` carries ``value``."""
    return (
        '{"version": "0", "id": "11111111-2222-3333-4444-555555555555", '
        '"detail-type": "OrderPlaced", "source": "sim2real.orders", '
        '"account": "123456789012", "time": "2024-01-01T00:00:00Z", '
        f'"region": "{ctx.region}", "resources": [], "detail": {{"n": {value}}}}}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
