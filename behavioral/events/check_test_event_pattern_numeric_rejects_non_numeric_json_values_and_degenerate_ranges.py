"""test-event-pattern-numeric-rejects-non-numeric-json-values-and-degenerate-ranges."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-numeric-rejects-non-numeric-json-values-and-degenerate-ranges"
GROUP = 'test-event-pattern'
SERVICES = ['events']


def _error_code_and_message(fn):
    """Call fn() and return the ClientError's (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c7", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """`numeric` never matches a numeric-looking JSON string, and TestEventPattern refuses a
    reversed numeric range and `numeric` nested in `anything-but` with InvalidEventPatternException.
    """
    ev = ctx.client("events")

    # --- numeric never matches a numeric-looking JSON string -------------------------------
    gt = {"detail": {"amount": [{"numeric": [">", 100]}]}}
    _expect(ev, gt, _event(ctx, detail={"amount": "150"}),
            False, "numeric must not coerce a JSON string, even one that looks numeric")
    _expect(ev, gt, _event(ctx, detail={"amount": 150}),
            True, "control: the same bound against the actual JSON number matches")

    # --- a reversed/degenerate range is refused, not evaluated -----------------------------
    # EventBridge validates bound ordering when the pattern is parsed, so this never evaluates.
    reversed_pattern = {"detail": {"amount": [{"numeric": [">", 100, "<", 50]}]}}
    code, message = _error_code_and_message(lambda: ev.test_event_pattern(
        EventPattern=json.dumps(reversed_pattern), Event=json.dumps(_event(ctx, detail={"amount": 75})),
    ))
    assert code == "InvalidEventPatternException", (
        f"expected InvalidEventPatternException for a reversed numeric range, got {code!r}"
    )
    expected_message = (
        "Event pattern is not valid. Reason: Bottom must be less than top\n"
        f' at [Source: (String)"{json.dumps(reversed_pattern)}"; line: 1, column: 55]'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- numeric has no nested anything-but form --------------------------------------------
    nested = {"detail": {"amount": [{"anything-but": {"numeric": [">", 100]}}]}}
    code2, message2 = _error_code_and_message(lambda: ev.test_event_pattern(
        EventPattern=json.dumps(nested), Event=json.dumps(_event(ctx, detail={"amount": 50})),
    ))
    assert code2 == "InvalidEventPatternException", (
        f"expected InvalidEventPatternException nesting numeric inside anything-but, got {code2!r}"
    )
    expected_message2 = (
        "Event pattern is not valid. Reason: Unsupported anything-but pattern: numeric\n"
        f' at [Source: (String)"{json.dumps(nested)}"; line: 1, column: 54]'
    )
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


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
