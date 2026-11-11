"""test-event-pattern-anything-but-over-array-valued-field-admits-any-escaping-element."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-anything-but-over-array-valued-field-admits-any-escaping-element"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """`anything-but` over an array-valued field admits the event when any element escapes the
    excluded set, even if excluded values are also present; empty arrays and absent fields do not match.
    """
    ev = ctx.client("events")

    # --- single excluded value --------------------------------------------------------------
    one = {"detail": {"tags": [{"anything-but": "blocked"}]}}
    _expect(ev, one, _event(ctx, detail={"tags": ["a", "b"]}),
            True, "no element equals the excluded value")
    _expect(ev, one, _event(ctx, detail={"tags": ["blocked"]}),
            False, "the only element equals the excluded value")
    _expect(ev, one, _event(ctx, detail={"tags": ["a", "blocked"]}),
            True, "one element escapes the excluded value even though the other carries it")
    _expect(ev, one, _event(ctx, detail={"tags": []}),
            False, "an empty array has no element that can escape the exclusion")

    # --- a list of excluded values: every element of the array must escape EVERY excluded
    # value for the array as a whole to be excluded; one escaping element is enough to admit ----
    many = {"detail": {"tags": [{"anything-but": ["blocked", "banned"]}]}}
    _expect(ev, many, _event(ctx, detail={"tags": ["a", "b"]}),
            True, "no element is in the excluded set")
    _expect(ev, many, _event(ctx, detail={"tags": ["blocked"]}),
            False, "the only element is the first excluded value")
    _expect(ev, many, _event(ctx, detail={"tags": ["banned"]}),
            False, "the only element is the second excluded value")
    _expect(ev, many, _event(ctx, detail={"tags": ["blocked", "banned"]}),
            False, "every element is in the excluded set")
    _expect(ev, many, _event(ctx, detail={"tags": ["a", "blocked", "banned"]}),
            True, "one escaping element admits the event even though both excluded values are also present")

    # --- a field the event does not carry at all cannot be admitted -------------------------
    _expect(ev, one, _event(ctx, detail={"other": ["a", "b"]}),
            False, "anything-but over an absent field must not match")




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
