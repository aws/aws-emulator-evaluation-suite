"""test-event-pattern-numeric-range-boundaries."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-numeric-range-boundaries"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`numeric` `>`, `>=`, `<`, `<=` and `=` are asserted just below, on and just above the bound;
    a two-sided range ANDs both halves, with negative/fractional operands; an absent field misses.
    """
    ev = ctx.client("events")

    # --- strictly greater than ------------------------------------------------------------
    gt = {"detail": {"amount": [{"numeric": [">", 100]}]}}
    _expect(ev, gt, _event(ctx, detail={"amount": 101}), True, "> is satisfied above the bound")
    _expect(ev, gt, _event(ctx, detail={"amount": 100}), False, "> must EXCLUDE the bound itself")
    _expect(ev, gt, _event(ctx, detail={"amount": 99}), False, "> is unsatisfied below the bound")

    # --- greater than or equal ------------------------------------------------------------
    ge = {"detail": {"amount": [{"numeric": [">=", 100]}]}}
    _expect(ev, ge, _event(ctx, detail={"amount": 101}), True, ">= is satisfied above the bound")
    _expect(ev, ge, _event(ctx, detail={"amount": 100}), True, ">= must INCLUDE the bound itself")
    _expect(ev, ge, _event(ctx, detail={"amount": 99}), False, ">= is unsatisfied below the bound")

    # --- strictly less than / less than or equal ------------------------------------------
    lt = {"detail": {"amount": [{"numeric": ["<", 100]}]}}
    _expect(ev, lt, _event(ctx, detail={"amount": 99}), True, "< is satisfied below the bound")
    _expect(ev, lt, _event(ctx, detail={"amount": 100}), False, "< must EXCLUDE the bound itself")
    _expect(ev, lt, _event(ctx, detail={"amount": 101}), False, "< is unsatisfied above the bound")

    le = {"detail": {"amount": [{"numeric": ["<=", 100]}]}}
    _expect(ev, le, _event(ctx, detail={"amount": 99}), True, "<= is satisfied below the bound")
    _expect(ev, le, _event(ctx, detail={"amount": 100}), True, "<= must INCLUDE the bound itself")
    _expect(ev, le, _event(ctx, detail={"amount": 101}), False, "<= is unsatisfied above the bound")

    # --- numeric equality -----------------------------------------------------------------
    eq = {"detail": {"amount": [{"numeric": ["=", 100]}]}}
    _expect(ev, eq, _event(ctx, detail={"amount": 100}), True, "= matches the exact number")
    _expect(ev, eq, _event(ctx, detail={"amount": 100.0}), True, "= matches the same value written 100.0")
    _expect(ev, eq, _event(ctx, detail={"amount": 100.5}), False, "= must not match a nearby number")

    # --- two-sided range: both operator/operand pairs must hold (AND, not OR) -------------
    band = {"detail": {"amount": [{"numeric": [">", 0, "<=", 100]}]}}
    _expect(ev, band, _event(ctx, detail={"amount": 50}), True, "value inside the range")
    _expect(ev, band, _event(ctx, detail={"amount": 100}), True, "upper bound is inclusive (<=)")
    _expect(ev, band, _event(ctx, detail={"amount": 0}), False, "lower bound is exclusive (>)")
    _expect(ev, band, _event(ctx, detail={"amount": 101}), False, "above the upper bound")
    _expect(ev, band, _event(ctx, detail={"amount": -1}), False,
            "below the lower bound -- both halves of the range must hold, so this is not an OR")

    # --- negative and fractional operands -------------------------------------------------
    neg = {"detail": {"delta": [{"numeric": [">=", -10, "<", -1.5]}]}}
    _expect(ev, neg, _event(ctx, detail={"delta": -10}), True, "negative inclusive lower bound")
    _expect(ev, neg, _event(ctx, detail={"delta": -1.75}), True, "fractional value inside the range")
    _expect(ev, neg, _event(ctx, detail={"delta": -1.5}), False, "fractional exclusive upper bound")
    _expect(ev, neg, _event(ctx, detail={"delta": 0}), False, "zero is outside a negative range")
    _expect(ev, neg, _event(ctx, detail={"delta": -10.0001}), False, "just below the lower bound")

    # --- an absent field cannot satisfy a range -------------------------------------------
    _expect(ev, gt, _event(ctx, detail={"other": 500}), False,
            "a numeric range over a field the event does not carry must not match")




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
