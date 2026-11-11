"""test-event-pattern-anything-but-mixed-string-number-list-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-anything-but-mixed-string-number-list-rejected"
GROUP = "test-event-pattern"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An `anything-but` list mixing strings and numbers is refused with an exact message, while
    an all-string list and an all-number list are accepted and match correctly.
    """
    ev = ctx.client("events")

    mixed = {"detail": {"state": [{"anything-but": ["initializing", 1]}]}}
    body = json.dumps(mixed)
    code, message = _error(
        lambda: ev.test_event_pattern(EventPattern=body, Event=json.dumps(_event(ctx)))
    )
    assert code == "InvalidEventPatternException", (
        f"a mixed string/number anything-but list must be rejected: expected "
        f"InvalidEventPatternException, got {code}\n  pattern = {body}"
    )
    expected = _pattern_message(body)
    assert message == expected, (
        f"TestEventPattern refused the mixed anything-but list with message {message!r}, "
        f"expected {expected!r}"
    )

    strings = {"detail": {"state": [{"anything-but": ["initializing", "stopping"]}]}}
    _expect_matches(ev, strings, _event(ctx, detail={"state": "running"}),
                    True, "a string outside an all-string anything-but list passes")
    _expect_matches(ev, strings, _event(ctx, detail={"state": "stopping"}),
                    False, "a string inside an all-string anything-but list is excluded")

    numbers = {"detail": {"code": [{"anything-but": [400, 500]}]}}
    _expect_matches(ev, numbers, _event(ctx, detail={"code": 200}),
                    True, "a number outside an all-number anything-but list passes")
    _expect_matches(ev, numbers, _event(ctx, detail={"code": 500}),
                    False, "a number inside an all-number anything-but list is excluded")


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


def _error(call) -> tuple[str, str]:
    """Run `call` and return the (code, message) of its AWS error; a success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Code>"), err.get("Message", "<missing Message>")
    raise AssertionError(f"expected the pattern to be refused; it SUCCEEDED: {result!r}")


def _pattern_message(body: str) -> str:
    """The exact InvalidEventPatternException message for a mixed anything-but list."""
    return (
        "Event pattern is not valid. Reason: Inside anything but list, either all values are "
        "number or string, mixed type is not supported\n"
        f' at [Source: (String)"{body}"; line: 1, column: 59]'
    )


def _expect_matches(ev, pattern: dict, event: dict, want: bool, why: str) -> None:
    resp = ev.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(event))
    result = resp["Result"]
    assert isinstance(result, bool), (
        f"TestEventPattern.Result must be a JSON boolean, got {result!r} ({type(result).__name__})"
    )
    assert result is want, (
        f"{why}: expected Result={want}, got {result}\n"
        f"  pattern = {json.dumps(pattern)}\n"
        f"  event   = {json.dumps(event)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
