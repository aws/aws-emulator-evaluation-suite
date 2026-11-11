"""test-event-pattern-multiple-filters-in-one-list-are-or-joined."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-multiple-filters-in-one-list-are-or-joined"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """A key's list can mix different operators, or a literal with an operator, and the key matches
    when any element matches, so a value only the second filter matches is still admitted.
    """
    ev = ctx.client("events")

    # --- a string-comparator and a numeric-comparator in the same list, OR-joined -----------
    mixed_ops = {"detail": {"state": [{"prefix": "ready"}, {"numeric": [">", 100]}]}}
    _expect(ev, mixed_ops, _event(ctx, detail={"state": "readyish"}),
            True, "the FIRST filter (prefix) matches")
    _expect(ev, mixed_ops, _event(ctx, detail={"state": 150}),
            True, "the SECOND filter (numeric) matches a value the first filter cannot even see")
    _expect(ev, mixed_ops, _event(ctx, detail={"state": "other"}),
            False, "neither filter matches")
    _expect(ev, mixed_ops, _event(ctx, detail={"state": "150"}),
            False, "the JSON string \"150\" matches neither: not a numeric value, "
            "and it does not start with the prefix")

    # --- a plain literal value mixed with an operator object in the same list ---------------
    mixed_literal = {"detail": {"tier": ["bronze", {"prefix": "go"}]}}
    _expect(ev, mixed_literal, _event(ctx, detail={"tier": "bronze"}),
            True, "the literal alternative matches")
    _expect(ev, mixed_literal, _event(ctx, detail={"tier": "gold"}),
            True, "the operator alternative matches a value the literal cannot")
    _expect(ev, mixed_literal, _event(ctx, detail={"tier": "silver"}),
            False, "neither alternative matches")




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


def _matches(ev, pattern, event) -> bool:
    """TestEventPattern's boolean verdict for one (pattern, event) pair."""
    resp = ev.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(event))
    result = resp["Result"]
    assert isinstance(result, bool), (
        f"TestEventPattern.Result must be a JSON boolean, got {result!r} ({type(result).__name__})"
    )
    return result


def _expect(ev, pattern, event, want: bool, why: str) -> None:
    """Assert TestEventPattern's verdict, reporting the pattern and event that disagreed."""
    got = _matches(ev, pattern, event)
    assert got is want, (
        f"{why}: expected Result={want}, got {got}\n"
        f"  pattern = {json.dumps(pattern)}\n"
        f"  event   = {json.dumps(event)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
