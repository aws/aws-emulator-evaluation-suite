"""test-event-pattern-string-content-filters."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-string-content-filters"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """prefix, suffix, equals-ignore-case and wildcard each match their anchored target and reject
    near-misses (substring, unanchored, wrong case), while exact matching stays case-sensitive.
    """
    ev = ctx.client("events")

    # --- prefix: anchored at the START of the string, not "contains" ----------------------
    pre = {"source": [{"prefix": "sim2real.ord"}]}
    _expect(ev, pre, _event(ctx, source="sim2real.orders"),
            True, "prefix matches a value that starts with the operand")
    _expect(ev, pre, _event(ctx, source="sim2real.ord"),
            True, "prefix matches a value equal to the operand")
    _expect(ev, pre, _event(ctx, source="x.sim2real.orders"),
            False, "prefix must be anchored at the start, not a substring test")
    _expect(ev, pre, _event(ctx, source="sim2real.payments"),
            False, "prefix must not match an unrelated value")
    _expect(ev, {"source": [{"prefix": "sim2real.Ord"}]}, _event(ctx, source="sim2real.orders"),
            False, "prefix is case-sensitive")

    # --- suffix: anchored at the END ------------------------------------------------------
    suf = {"detail": {"key": [{"suffix": ".json"}]}}
    _expect(ev, suf, _event(ctx, detail={"key": "reports/2024/summary.json"}),
            True, "suffix matches a value that ends with the operand")
    _expect(ev, suf, _event(ctx, detail={"key": "summary.json.bak"}),
            False, "suffix must be anchored at the end, not a substring test")
    _expect(ev, suf, _event(ctx, detail={"key": "summary.JSON"}),
            False, "suffix is case-sensitive")

    # --- equals-ignore-case: case-insensitive but still WHOLE-value ----------------------
    eic = {"detail-type": [{"equals-ignore-case": "orderplaced"}]}
    _expect(ev, eic, _event(ctx, **{"detail-type": "OrderPlaced"}),
            True, "equals-ignore-case matches a differently-cased value")
    _expect(ev, eic, _event(ctx, **{"detail-type": "ORDERPLACED"}),
            True, "equals-ignore-case matches an upper-cased value")
    _expect(ev, eic, _event(ctx, **{"detail-type": "OrderPlacedV2"}),
            False, "equals-ignore-case compares the whole value, not a prefix")
    _expect(ev, eic, _event(ctx, **{"detail-type": "OrderCancelled"}),
            False, "equals-ignore-case must not match a different word")
    # ...and the ordinary exact matcher next door stays case-SENSITIVE.
    _expect(ev, {"detail-type": ["orderplaced"]}, _event(ctx, **{"detail-type": "OrderPlaced"}),
            False, "exact matching must remain case-sensitive alongside equals-ignore-case")

    # --- wildcard: `*` is zero-or-more characters, and the pattern spans the WHOLE value --
    wc = {"detail": {"path": [{"wildcard": "/api/*/users"}]}}
    _expect(ev, wc, _event(ctx, detail={"path": "/api/v1/users"}),
            True, "wildcard matches with the star standing for one segment")
    _expect(ev, wc, _event(ctx, detail={"path": "/api//users"}),
            True, "wildcard star matches the empty string")
    _expect(ev, wc, _event(ctx, detail={"path": "/api/v1/users/42"}),
            False, "wildcard must span the whole value, so a longer value must not match")
    _expect(ev, wc, _event(ctx, detail={"path": "/prefix/api/v1/users"}),
            False, "wildcard must be anchored at the start of the value")
    _expect(ev, wc, _event(ctx, detail={"path": "/api/v1/USERS"}),
            False, "wildcard is case-sensitive")
    # A star at the end absorbs any tail, including nothing at all.
    tail = {"detail": {"path": [{"wildcard": "/api/*"}]}}
    _expect(ev, tail, _event(ctx, detail={"path": "/api/"}),
            True, "a trailing star matches an empty tail")
    _expect(ev, tail, _event(ctx, detail={"path": "/api/v1/users/42"}),
            True, "a trailing star absorbs an arbitrary tail")
    _expect(ev, tail, _event(ctx, detail={"path": "/internal/api/v1"}),
            False, "a trailing star does not make the pattern unanchored at the start")


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
