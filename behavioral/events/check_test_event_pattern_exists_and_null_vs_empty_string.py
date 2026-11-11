"""test-event-pattern-exists-and-null-vs-empty-string."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-exists-and-null-vs-empty-string"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`exists` tests presence (a falsy value such as "", 0 or false is present), and absent, JSON null
    and the empty string are three distinct values to exact matching.
    """
    ev = ctx.client("events")

    # --- exists: true ---------------------------------------------------------------------
    present = {"detail": {"customer": [{"exists": True}]}}
    _expect(ev, present, _event(ctx, detail={"customer": "C1"}),
            True, "exists:true matches a present string leaf")
    _expect(ev, present, _event(ctx, detail={"customer": 0}),
            True, "exists:true matches a present numeric leaf, including the falsy value 0")
    _expect(ev, present, _event(ctx, detail={"customer": False}),
            True, "exists:true matches a present boolean leaf, including false")
    _expect(ev, present, _event(ctx, detail={"customer": ""}),
            True, "exists:true matches a present leaf whose value is the empty string")
    _expect(ev, present, _event(ctx, detail={"other": "C1"}),
            False, "exists:true must not match when the field is absent")
    _expect(ev, present, _event(ctx, detail={}),
            False, "exists:true must not match an empty detail")

    # --- exists: false --------------------------------------------------------------------
    absent = {"detail": {"customer": [{"exists": False}]}}
    _expect(ev, absent, _event(ctx, detail={"other": "C1"}),
            True, "exists:false matches when the field is absent but a sibling is present")
    _expect(ev, absent, _event(ctx, detail={"customer": "C1"}),
            False, "exists:false must not match when the field is present")
    _expect(ev, absent, _event(ctx, detail={"customer": ""}),
            False, "exists:false must not match a present-but-empty-string field")
    _expect(ev, absent, _event(ctx, detail={"customer": 0}),
            False, "exists:false must not match a present-but-zero field")
    _expect(ev, absent, _event(ctx, detail={"customer": False}),
            False, "exists:false must not match a present-but-false field")

    # exists:false composes with an ordinary value key by AND, so both must hold.
    composed = {"source": ["sim2real.orders"], "detail": {"customer": [{"exists": False}]}}
    _expect(ev, composed, _event(ctx, source="sim2real.orders", detail={"other": 1}),
            True, "both the value key and the exists:false key are satisfied")
    _expect(ev, composed, _event(ctx, source="sim2real.orders", detail={"customer": "C1"}),
            False, "exists:false unsatisfied fails the whole pattern")
    _expect(ev, composed, _event(ctx, source="sim2real.payments", detail={"other": 1}),
            False, "the value key unsatisfied fails the whole pattern")

    # --- null is a value, and it is not "" and not absence ---------------------------------
    null_pat = {"detail": {"customer": [None]}}
    _expect(ev, null_pat, _event(ctx, detail={"customer": None}),
            True, "a null pattern value matches a null event value")
    _expect(ev, null_pat, _event(ctx, detail={"customer": ""}),
            False, "a null pattern value must NOT match the empty string")
    _expect(ev, null_pat, _event(ctx, detail={"customer": "null"}),
            False, "a null pattern value must NOT match the string \"null\"")
    _expect(ev, null_pat, _event(ctx, detail={}),
            False, "a null pattern value must NOT match an absent field")

    # --- the empty string is a value too --------------------------------------------------
    empty_pat = {"detail": {"customer": [""]}}
    _expect(ev, empty_pat, _event(ctx, detail={"customer": ""}),
            True, "an empty-string pattern value matches an empty-string event value")
    _expect(ev, empty_pat, _event(ctx, detail={"customer": None}),
            False, "an empty-string pattern value must NOT match null")
    _expect(ev, empty_pat, _event(ctx, detail={}),
            False, "an empty-string pattern value must NOT match an absent field")
    _expect(ev, empty_pat, _event(ctx, detail={"customer": " "}),
            False, "an empty-string pattern value must NOT match a single space")




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
