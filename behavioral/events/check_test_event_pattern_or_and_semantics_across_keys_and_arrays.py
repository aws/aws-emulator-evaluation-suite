"""test-event-pattern-or-and-semantics-across-keys-and-arrays."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-or-and-semantics-across-keys-and-arrays"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c7", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A value list under one key is OR, multiple keys are AND (an absent key fails), a pattern
    value matches any element of an array field, and top-level `$or` expresses OR across keys.
    """
    ev = ctx.client("events")

    # --- (1) a list under one key is OR ---------------------------------------------------
    two_sources = {"source": ["sim2real.orders", "sim2real.payments"]}
    _expect(ev, two_sources, _event(ctx, source="sim2real.orders"),
            True, "first alternative in an OR list matches")
    _expect(ev, two_sources, _event(ctx, source="sim2real.payments"),
            True, "second alternative in an OR list matches")
    _expect(ev, two_sources, _event(ctx, source="sim2real.shipping"),
            False, "a value in neither alternative must not match")

    # --- (2) multiple keys are AND --------------------------------------------------------
    both = {"source": ["sim2real.orders"], "detail-type": ["OrderPlaced"]}
    _expect(ev, both, _event(ctx, source="sim2real.orders", **{"detail-type": "OrderPlaced"}),
            True, "both keys satisfied")
    _expect(ev, both, _event(ctx, source="sim2real.orders", **{"detail-type": "OrderCancelled"}),
            False, "second key unsatisfied must fail the whole pattern (AND, not OR)")
    _expect(ev, both, _event(ctx, source="sim2real.payments", **{"detail-type": "OrderPlaced"}),
            False, "first key unsatisfied must fail the whole pattern (AND, not OR)")

    # AND also holds between sibling keys inside `detail`.
    two_detail_keys = {"detail": {"state": ["PROD"], "tier": ["gold"]}}
    _expect(ev, two_detail_keys, _event(ctx, detail={"state": "PROD", "tier": "gold"}),
            True, "both detail keys satisfied")
    _expect(ev, two_detail_keys, _event(ctx, detail={"state": "PROD", "tier": "silver"}),
            False, "sibling detail keys are AND")

    # A pattern key the event does not carry at all fails -- absence is not a wildcard.
    _expect(ev, both, _event(ctx, source="sim2real.orders", **{"detail-type": "OrderPlaced"}),
            True, "control for the absent-key case")
    absent_key = {"source": ["sim2real.orders"], "detail": {"tier": ["gold"]}}
    _expect(ev, absent_key, _event(ctx, source="sim2real.orders", detail={}),
            False, "a pattern key absent from the event must not match")

    # --- (3) a scalar pattern value against an ARRAY-valued event field -------------------
    arn = f"arn:aws:events:{ctx.region}:123456789012:rule/sim2real-behav-any-element"
    other = f"arn:aws:events:{ctx.region}:123456789012:rule/sim2real-behav-other"
    _expect(ev, {"resources": [arn]}, _event(ctx, resources=[other, arn]),
            True, "a pattern value matching ANY element of the event's array matches")
    _expect(ev, {"resources": [arn]}, _event(ctx, resources=[other]),
            False, "a pattern value matching NO element of the event's array must not match")
    _expect(ev, {"resources": [arn]}, _event(ctx, resources=[]),
            False, "an empty event array cannot satisfy a value pattern")
    # Both sides lists: matching is "some element of each side agrees".
    _expect(ev, {"detail": {"tags": ["blue", "green"]}},
            _event(ctx, detail={"tags": ["red", "green"]}),
            True, "OR list vs event array matches on the single shared element")
    _expect(ev, {"detail": {"tags": ["blue", "green"]}},
            _event(ctx, detail={"tags": ["red", "yellow"]}),
            False, "OR list vs event array with no shared element must not match")

    # --- (4) top-level $or is the only cross-key disjunction ------------------------------
    disjunction = {
        "$or": [
            {"source": ["sim2real.orders"]},
            {"detail-type": ["Emergency"]},
        ]
    }
    _expect(ev, disjunction, _event(ctx, source="sim2real.orders",
                                    **{"detail-type": "OrderPlaced"}),
            True, "$or satisfied by its first branch")
    _expect(ev, disjunction, _event(ctx, source="sim2real.payments",
                                    **{"detail-type": "Emergency"}),
            True, "$or satisfied by its second branch")
    _expect(ev, disjunction, _event(ctx, source="sim2real.payments",
                                    **{"detail-type": "OrderPlaced"}),
            False, "$or with neither branch satisfied must not match")


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
