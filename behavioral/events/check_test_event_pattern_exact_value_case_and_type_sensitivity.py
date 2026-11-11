"""test-event-pattern-exact-value-case-and-type-sensitivity."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-exact-value-case-and-type-sensitivity"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """Exact-value matching is case-sensitive and JSON-type-sensitive (5 vs "5", true vs "true"),
    treats 5 and 5.0 as one number, and requires nested pattern paths to match the event's nesting.
    """
    ev = ctx.client("events")

    # --- case sensitivity on a top-level string field -------------------------------------
    _expect(ev, {"source": ["sim2real.Orders"]}, _event(ctx, source="sim2real.Orders"),
            True, "exact source match on identical bytes")
    _expect(ev, {"source": ["sim2real.Orders"]}, _event(ctx, source="sim2real.orders"),
            False, "source match must be case-sensitive")
    _expect(ev, {"detail-type": ["OrderPlaced"]}, _event(ctx, **{"detail-type": "OrderPlaced"}),
            True, "exact detail-type match")
    _expect(ev, {"detail-type": ["OrderPlaced"]}, _event(ctx, **{"detail-type": "orderplaced"}),
            False, "detail-type match must be case-sensitive")

    # --- JSON type sensitivity inside detail ----------------------------------------------
    _expect(ev, {"detail": {"qty": [5]}}, _event(ctx, detail={"qty": 5}),
            True, "number pattern matches the same number")
    _expect(ev, {"detail": {"qty": [5]}}, _event(ctx, detail={"qty": "5"}),
            False, "number pattern must NOT match the string \"5\"")
    _expect(ev, {"detail": {"qty": ["5"]}}, _event(ctx, detail={"qty": "5"}),
            True, "string pattern matches the same string")
    _expect(ev, {"detail": {"qty": ["5"]}}, _event(ctx, detail={"qty": 5}),
            False, "string pattern must NOT match the number 5")

    # --- boolean vs the string spelling of a boolean --------------------------------------
    _expect(ev, {"detail": {"paid": [True]}}, _event(ctx, detail={"paid": True}),
            True, "boolean pattern matches the same boolean")
    _expect(ev, {"detail": {"paid": [True]}}, _event(ctx, detail={"paid": "true"}),
            False, "boolean pattern must NOT match the string \"true\"")

    # --- numeric equality is on VALUE, so 5 and 5.0 are the same JSON number -------------
    _expect(ev, {"detail": {"qty": [5]}}, _event(ctx, detail={"qty": 5.0}),
            True, "5 and 5.0 are the same JSON number")

    # --- nested paths must line up with the event's own structure -------------------------
    _expect(ev, {"detail": {"order": {"id": ["A1"]}}},
            _event(ctx, detail={"order": {"id": "A1"}}),
            True, "nested pattern path matches the nested event path")
    _expect(ev, {"detail": {"order": {"id": ["A1"]}}},
            _event(ctx, detail={"id": "A1"}),
            False, "a nested pattern path must not match a flattened event")
    _expect(ev, {"detail": {"id": ["A1"]}},
            _event(ctx, detail={"order": {"id": "A1"}}),
            False, "a flat pattern path must not match a nested event")




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
