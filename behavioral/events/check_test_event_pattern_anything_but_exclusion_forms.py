"""test-event-pattern-anything-but-exclusion-forms."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-anything-but-exclusion-forms"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`anything-but` excludes a single string, every element of a string or number list, and a
    nested `prefix` namespace, while still admitting values outside the excluded set.
    """
    ev = ctx.client("events")

    # --- single string operand ------------------------------------------------------------
    one = {"detail": {"state": [{"anything-but": "initializing"}]}}
    _expect(ev, one, _event(ctx, detail={"state": "running"}),
            True, "anything-but admits a value other than the excluded one")
    _expect(ev, one, _event(ctx, detail={"state": "initializing"}),
            False, "anything-but must exclude the operand itself")
    # The comparison it negates is the byte-exact one, so case matters here too.
    _expect(ev, one, _event(ctx, detail={"state": "Initializing"}),
            True, "anything-but negates a case-SENSITIVE comparison, so a recased value passes")
    # And it is whole-value, not substring: a longer value containing the operand still passes.
    _expect(ev, one, _event(ctx, detail={"state": "initializing-slowly"}),
            True, "anything-but excludes the whole value, not any value containing it")

    # --- list of strings: EVERY element is excluded ----------------------------------------
    many = {"detail": {"state": [{"anything-but": ["initializing", "stopping", "failed"]}]}}
    _expect(ev, many, _event(ctx, detail={"state": "running"}),
            True, "a value in none of the excluded values passes")
    _expect(ev, many, _event(ctx, detail={"state": "initializing"}),
            False, "the FIRST excluded value must be excluded")
    _expect(ev, many, _event(ctx, detail={"state": "stopping"}),
            False, "a MIDDLE excluded value must be excluded")
    _expect(ev, many, _event(ctx, detail={"state": "failed"}),
            False, "the LAST excluded value must be excluded")

    # --- list of numbers ------------------------------------------------------------------
    nums = {"detail": {"code": [{"anything-but": [400, 500]}]}}
    _expect(ev, nums, _event(ctx, detail={"code": 200}),
            True, "a number outside the excluded set passes")
    _expect(ev, nums, _event(ctx, detail={"code": 400}),
            False, "the first excluded number must be excluded")
    _expect(ev, nums, _event(ctx, detail={"code": 500}),
            False, "the second excluded number must be excluded")
    _expect(ev, nums, _event(ctx, detail={"code": 500.0}),
            False, "500.0 is the same JSON number as 500, so it is excluded too")

    # --- nested prefix: excludes an entire namespace, not one literal ----------------------
    pre = {"source": [{"anything-but": {"prefix": "sim2real.internal."}}]}
    _expect(ev, pre, _event(ctx, source="sim2real.orders"),
            True, "a source outside the excluded prefix passes")
    _expect(ev, pre, _event(ctx, source="sim2real.internal.audit"),
            False, "a source under the excluded prefix must be excluded")
    _expect(ev, pre, _event(ctx, source="sim2real.internal."),
            False, "a source equal to the excluded prefix must be excluded")
    _expect(ev, pre, _event(ctx, source="x.sim2real.internal.audit"),
            True, "the excluded prefix is anchored at the start, so this is not excluded")




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
