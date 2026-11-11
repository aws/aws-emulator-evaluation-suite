"""test-event-pattern-malformed-operator-rejection."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-malformed-operator-rejection"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Malformed event patterns are refused by TestEventPattern and PutRule with exact messages,
    each minimally-corrected form is accepted, and a refused PutRule leaves the stored rule intact.
    """
    ev = ctx.client("events")

    # Leaf values must be wrapped in an array. A bare scalar is not a one-element shorthand.
    _expect_pattern_invalid(ev, {"source": "sim2real.orders"},
                            "a leaf value not wrapped in an array",
                            '"source" must be an object or an array', 13)
    _expect_pattern_valid(ev, {"source": ["sim2real.orders"]},
                          _event(ctx), True, "the array-wrapped correction is accepted and matches")

    # An operator key the language does not define cannot be silently ignored.
    _expect_pattern_invalid(ev, {"source": [{"starts-with": "sim2real."}]},
                            "an operator key that does not exist in the language",
                            "Unrecognized match type starts-with", 30)
    _expect_pattern_valid(ev, {"source": [{"prefix": "sim2real."}]},
                          _event(ctx), True, "the real operator name is accepted and matches")

    # `numeric` operands come in operator/value pairs; a dangling operator has no operand.
    _expect_pattern_invalid(ev, {"detail": {"amount": [{"numeric": [">"]}]}},
                            "a numeric comparison with an operator but no operand",
                            "Value of > must be numeric", 41)
    _expect_pattern_valid(ev, {"detail": {"amount": [{"numeric": [">", 100]}]}},
                          _event(ctx, detail={"amount": 101}), True,
                          "the completed numeric comparison is accepted and matches")

    # `exists` takes a JSON boolean, not the string spelling of one.
    _expect_pattern_invalid(ev, {"detail": {"customer": [{"exists": "true"}]}},
                            "an exists operand that is a string rather than a boolean",
                            "exists match pattern must be either true or false.", 38)
    _expect_pattern_valid(ev, {"detail": {"customer": [{"exists": True}]}},
                          _event(ctx, detail={"customer": "C1"}), True,
                          "the boolean exists operand is accepted and matches")

    # The root of a pattern is a JSON object. An array root has no field to bind to.
    _expect_pattern_invalid(ev, ["sim2real.orders"], "a JSON array at the root of the pattern",
                            "Filter is not an object", 2)
    # ...and neither does a bare scalar root.
    _expect_pattern_invalid(ev, "sim2real.orders", "a bare JSON string at the root of the pattern",
                            "Filter is not an object", 2)
    _expect_pattern_valid(ev, {"source": ["sim2real.orders"]},
                          _event(ctx), True, "an object root is accepted and matches")

    name = ctx.unique_name("sim2real-behav-")
    good = json.dumps({"source": ["sim2real.orders"]})
    ev.put_rule(Name=name, EventPattern=good, State="ENABLED",
                Description="sim2real behavioral: malformed-pattern rejection",
                Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=name))

    stored = ev.describe_rule(Name=name)["EventPattern"]
    assert json.loads(stored) == json.loads(good), (
        f"setup failed: rule {name} stored EventPattern {stored!r}, expected {good!r}"
    )

    for pattern, why, reason, column in [
        ({"source": "sim2real.orders"}, "a leaf value not wrapped in an array",
         '"source" must be an object or an array', 13),
        ({"source": [{"starts-with": "sim2real."}]}, "an operator key that does not exist",
         "Unrecognized match type starts-with", 30),
        ({"detail": {"amount": [{"numeric": [">"]}]}}, "a dangling numeric operator",
         "Value of > must be numeric", 41),
        ({"detail": {"customer": [{"exists": "true"}]}}, "a non-boolean exists operand",
         "exists match pattern must be either true or false.", 38),
        (["sim2real.orders"], "a JSON array at the pattern root", "Filter is not an object", 2),
    ]:
        body = json.dumps(pattern)
        code, message = _error(lambda: ev.put_rule(Name=name, EventPattern=body, State="ENABLED"))
        assert code == "InvalidEventPatternException", (
            f"PutRule must reject {why}: expected InvalidEventPatternException, got {code}\n"
            f"  pattern = {body}"
        )
        expected = _pattern_message(body, reason, column)
        assert message == expected, (
            f"PutRule refused {why} with message {message!r}, expected {expected!r}"
        )
        after = ev.describe_rule(Name=name)
        assert json.loads(after["EventPattern"]) == json.loads(good), (
            f"PutRule rejected {why} but the stored EventPattern changed to "
            f"{after['EventPattern']!r}; a refused upsert must leave the rule byte-identical"
        )
        assert after["State"] == "ENABLED", (
            f"PutRule rejected {why} but the rule State changed to {after['State']!r}"
        )

    # A valid upsert still works, so the refusals were specific to the pattern.
    better = json.dumps({"source": ["sim2real.orders"], "detail-type": ["OrderPlaced"]})
    ev.put_rule(Name=name, EventPattern=better, State="ENABLED")
    final = ev.describe_rule(Name=name)["EventPattern"]
    assert json.loads(final) == json.loads(better), (
        f"control failed: after a valid upsert the rule holds {final!r}, expected {better!r}"
    )



def _event(ctx, **over):
    """A complete, well-formed EventBridge envelope, with any field overridable."""
    event = {
        "id": "11111111-2222-3333-4444-555555555555",
        "version": "0",
        "detail-type": "OrderPlaced",
        "source": "sim2real.orders",
        "account": "123456789012",
        "time": "2024-01-01T00:00:00Z",
        "region": ctx.region,
        "resources": [],
        "detail": {},
    }
    event.update(over)
    return event


def _error(call) -> tuple[str, str]:
    """Run `call` and return the (code, message) of its AWS error; a success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Code>"), err.get("Message", "<missing Message>")
    raise AssertionError(f"expected the malformed pattern to be refused; it SUCCEEDED: {result!r}")


def _pattern_message(body: str, reason: str, column: int) -> str:
    """The exact InvalidEventPatternException message: the reason and parser position in `body`."""
    return (
        f"Event pattern is not valid. Reason: {reason}\n"
        f' at [Source: (String)"{body}"; line: 1, column: {column}]'
    )


def _expect_pattern_invalid(ev, pattern, why: str, reason: str, column: int) -> None:
    """TestEventPattern must refuse to evaluate a structurally malformed pattern, saying why."""
    body = json.dumps(pattern)
    code, message = _error(
        lambda: ev.test_event_pattern(EventPattern=body, Event=json.dumps({"source": "x"}))
    )
    assert code == "InvalidEventPatternException", (
        f"TestEventPattern must reject {why}: expected InvalidEventPatternException, got {code}\n"
        f"  pattern = {body}"
    )
    expected = _pattern_message(body, reason, column)
    assert message == expected, (
        f"TestEventPattern refused {why} with message {message!r}, expected {expected!r}"
    )


def _expect_pattern_valid(ev, pattern, event, want: bool, why: str) -> None:
    """TestEventPattern must accept the pattern and return the expected verdict."""
    resp = ev.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(event))
    result = resp["Result"]
    assert isinstance(result, bool), (
        f"TestEventPattern.Result must be a JSON boolean, got {result!r} ({type(result).__name__})"
    )
    assert result is want, (
        f"{why}: expected Result={want}, got {result}\n"
        f"  pattern = {json.dumps(pattern)}\n"
        f"  event   = {json.dumps(event)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
