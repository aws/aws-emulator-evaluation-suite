"""test-event-pattern-exists-treats-every-object-leaf-and-the-empty-array-as-absent."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-exists-treats-every-object-leaf-and-the-empty-array-as-absent"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """`exists` treats any JSON object leaf (empty or not) and an empty array as absent, while a
    non-empty array and null are present; `exists: false` is the complement throughout.
    """
    ev = ctx.client("events")
    exists_true = {"detail": {"items": [{"exists": True}]}}
    exists_false = {"detail": {"items": [{"exists": False}]}}

    # --- a JSON object leaf is absent regardless of whether it is empty --------------------
    _expect(ev, exists_true, _event(ctx, detail={"items": {}}),
            False, "exists:true must not match an empty-object leaf")
    _expect(ev, exists_false, _event(ctx, detail={"items": {}}),
            True, "exists:false must match an empty-object leaf, like a truly absent field")
    _expect(ev, exists_true, _event(ctx, detail={"items": {"k": "v", "k2": 2}}),
            False, "exists:true must not match a NON-empty-object leaf either")
    _expect(ev, exists_false, _event(ctx, detail={"items": {"k": "v", "k2": 2}}),
            True, "exists:false must match a non-empty-object leaf too")

    # --- a JSON array leaf depends on emptiness, unlike an object --------------------------
    _expect(ev, exists_true, _event(ctx, detail={"items": []}),
            False, "exists:true must not match an empty-array leaf")
    _expect(ev, exists_false, _event(ctx, detail={"items": []}),
            True, "exists:false must match an empty-array leaf, like a truly absent field")
    _expect(ev, exists_true, _event(ctx, detail={"items": ["a"]}),
            True, "exists:true MUST match a non-empty-array leaf -- unlike the object case")
    _expect(ev, exists_false, _event(ctx, detail={"items": ["a"]}),
            False, "exists:false must not match a non-empty-array leaf")

    # --- JSON null stays on the present side, like a non-empty array -----------------------
    _expect(ev, exists_true, _event(ctx, detail={"items": None}),
            True, "exists:true must match a null leaf -- null is present, unlike {} or []")
    _expect(ev, exists_false, _event(ctx, detail={"items": None}),
            False, "exists:false must not match a null leaf")

    # --- truly absent agrees with {} and [], for the control --------------------------------
    _expect(ev, exists_true, _event(ctx, detail={}),
            False, "control: exists:true must not match a truly absent field")
    _expect(ev, exists_false, _event(ctx, detail={}),
            True, "control: exists:false must match a truly absent field")




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
