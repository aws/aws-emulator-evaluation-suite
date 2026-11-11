"""test-event-pattern-anything-but-nested-suffix-equals-ignore-case-and-wildcard-forms."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-anything-but-nested-suffix-equals-ignore-case-and-wildcard-forms"
GROUP = 'test-event-pattern'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`anything-but` nested with `suffix`, `equals-ignore-case` or `wildcard` excludes every value the
    inner comparator would match and admits every value it would not.
    """
    ev = ctx.client("events")

    # --- anything-but nested suffix: excludes every value ENDING with the operand -----------
    suf = {"detail": {"key": [{"anything-but": {"suffix": ".tmp"}}]}}
    _expect(ev, suf, _event(ctx, detail={"key": "report.json"}),
            True, "a value not ending with the excluded suffix is admitted")
    _expect(ev, suf, _event(ctx, detail={"key": "report.tmp"}),
            False, "a value ending with the excluded suffix must be excluded")
    _expect(ev, suf, _event(ctx, detail={"key": "report.TMP"}),
            True, "the nested suffix comparison stays case-sensitive, so a recased suffix is admitted")

    # --- anything-but nested equals-ignore-case: excludes every value equal UP TO CASE -------
    eic = {"detail": {"state": [{"anything-but": {"equals-ignore-case": "blocked"}}]}}
    _expect(ev, eic, _event(ctx, detail={"state": "running"}),
            True, "a value that is not a case-variant of the excluded word is admitted")
    _expect(ev, eic, _event(ctx, detail={"state": "Blocked"}),
            False, "a differently-cased variant of the excluded word must be excluded")
    _expect(ev, eic, _event(ctx, detail={"state": "BLOCKED"}),
            False, "the upper-cased variant of the excluded word must be excluded too")

    # --- anything-but nested wildcard: excludes every value the glob spans -------------------
    wc = {"detail": {"path": [{"anything-but": {"wildcard": "/internal/*"}}]}}
    _expect(ev, wc, _event(ctx, detail={"path": "/public/users"}),
            True, "a value outside the excluded glob is admitted")
    _expect(ev, wc, _event(ctx, detail={"path": "/internal/audit"}),
            False, "a value the excluded glob spans must be excluded")
    _expect(ev, wc, _event(ctx, detail={"path": "/internal/"}),
            False, "the glob's star matches an empty tail, so the bare prefix is excluded too")
    _expect(ev, wc, _event(ctx, detail={"path": "/other/internal/audit"}),
            True, "the excluded glob is anchored at the start, so this value is admitted")




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
