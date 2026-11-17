"""test-event-pattern-numeric-skips-an-event-number-no-double-represents."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-numeric-skips-an-event-number-no-double-represents"
GROUP = 'event-pattern-language'
SERVICES = ['events']

_ABOVE = {"detail": {"n": [{"numeric": [">", 1]}]}}
_BELOW = {"detail": {"n": [{"numeric": ["<", 1e30]}]}}
_BAND = {"detail": {"n": [{"numeric": [">", 1, "<", 1e30]}]}}
_PRESENT = {"detail": {"n": [{"exists": True}]}}


def _representable(value: int) -> bool:
    """Whether ``value`` survives a round trip through an IEEE 754 binary64 double."""
    return int(float(value)) == value


@tags("axis:happy-path", "cap:c7", "concern:eventing", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A numeric comparison reads an event number only where a binary64 double represents it
    exactly; exact-value matching and `exists` still see the very numbers it skips.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
    """
    ev = ctx.client("events")

    # Above 2**53 a double carries only the even integers, so a run of consecutive values alternates
    # between representable and not, which no single verdict could be mistaken for.
    values = [2 ** 53 + offset for offset in range(1, 9)]
    exact = [v for v in values if _representable(v)]
    assert len(exact) == 4 and exact == [v for v in values if v % 2 == 0], (
        f"derivation error: exactly the even half of {values!r} must be exact doubles, got {exact!r}"
    )

    for value in values:
        want = _representable(value)
        event = _event(ctx, value)

        # Both directions are satisfied by the magnitude of every value here, so a false verdict
        # means the comparison never read a number, not that the comparison came out the other way.
        _expect(ev, _ABOVE, event, want,
                f"a lower-bounded comparison reads {value} only as an exact double")
        _expect(ev, _BELOW, event, want,
                f"an upper-bounded comparison reads {value} only as an exact double")
        _expect(ev, _BAND, event, want,
                f"a two-sided range reads {value} only as an exact double")

        # The same literal is still the value the event carries, so the skip belongs to the
        # comparison alone.
        _expect(ev, {"detail": {"n": [value]}}, event, True,
                f"exact-value matching must match the event's own number {value}")
        _expect(ev, _PRESENT, event, True,
                f"the field carrying {value} must still be present to `exists`")


def _event(ctx, value: int) -> str:
    """A complete EventBridge envelope whose `detail.n` carries ``value``."""
    return (
        '{"version": "0", "id": "11111111-2222-3333-4444-555555555555", '
        '"detail-type": "OrderPlaced", "source": "sim2real.orders", '
        '"account": "123456789012", "time": "2024-01-01T00:00:00Z", '
        f'"region": "{ctx.region}", "resources": [], "detail": {{"n": {value}}}}}'
    )


def _expect(ev, pattern: dict, event: str, want: bool, why: str) -> None:
    """Assert TestEventPattern's verdict, quoting the pattern and event that disagreed."""
    pattern_text = json.dumps(pattern)
    got = ev.test_event_pattern(EventPattern=pattern_text, Event=event)["Result"]
    assert got is want, (
        f"{why}: expected Result={want}, got {got!r}\n"
        f"  pattern = {pattern_text}\n  event = {event}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
