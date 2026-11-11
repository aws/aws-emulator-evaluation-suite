"""test-event-pattern-exists-false-matches-when-an-intermediate-parent-is-missing."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-exists-false-matches-when-an-intermediate-parent-is-missing"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """`exists: false` on a nested leaf matches whether the leaf or its parent object is missing, and
    `exists: true` needs the whole path present; either composes by AND with a sibling key.
    """
    ev = ctx.client("events")
    leaf_absent = {"detail": {"order": {"customer": [{"exists": False}]}}}

    _expect(ev, leaf_absent, _event(ctx, detail={}),
            True, "exists:false matches when the whole PARENT object 'order' is missing")
    _expect(ev, leaf_absent, _event(ctx, detail={"order": {"other": 1}}),
            True, "exists:false matches when 'order' is present but the leaf 'customer' is missing")
    _expect(ev, leaf_absent, _event(ctx, detail={"order": {"customer": "C1"}}),
            False, "exists:false must not match when the leaf 'customer' is present")

    # The same distinction, inverted with exists:true.
    leaf_present = {"detail": {"order": {"customer": [{"exists": True}]}}}
    _expect(ev, leaf_present, _event(ctx, detail={}),
            False, "exists:true must not match when the parent 'order' is missing")
    _expect(ev, leaf_present, _event(ctx, detail={"order": {"other": 1}}),
            False, "exists:true must not match when the parent is present but the leaf is missing")
    _expect(ev, leaf_present, _event(ctx, detail={"order": {"customer": "C1"}}),
            True, "exists:true must match when the whole path down to the leaf is present")

    # exists:false composes by AND with a sibling value key at the SAME nesting level as the
    # missing parent, so the whole pattern still fails if that sibling is unsatisfied.
    composed = {"source": ["sim2real.orders"], "detail": {"order": {"customer": [{"exists": False}]}}}
    _expect(ev, composed, _event(ctx, source="sim2real.orders", detail={}),
            True, "both the source key and the missing-parent exists:false are satisfied")
    _expect(ev, composed, _event(ctx, source="sim2real.payments", detail={}),
            False, "the source key alone unsatisfied fails the whole pattern")




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
