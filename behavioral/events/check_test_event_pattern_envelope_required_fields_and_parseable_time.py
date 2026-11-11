"""test-event-pattern-envelope-required-fields-and-parseable-time."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-envelope-required-fields-and-parseable-time"
GROUP = 'test-event-pattern'
SERVICES = ['events']


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_REQUIRED = ("id", "detail-type", "source", "account", "time", "region")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestEventPattern refuses an Event missing any of six envelope fields, an unparseable time or
    non-JSON with ValidationException and exact messages; missing resources or detail still matches.
    """
    ev = ctx.client("events")
    pattern = json.dumps({"source": ["sim2real.envelope"]})
    full = {
        "id": "00000000-0000-0000-0000-000000000001",
        "detail-type": "Sim2realEnvelope",
        "source": "sim2real.envelope",
        "account": ctx.account,
        "time": "2024-01-01T00:00:00Z",
        "region": ctx.region,
        "resources": [],
        "detail": {"k": "v"},
    }

    control = ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(full))
    assert control["Result"] is True, f"the complete envelope did not match its source pattern: {control!r}"

    for field in _REQUIRED:
        event = {k: v for k, v in full.items() if k != field}
        code, message = _error(lambda e=event: ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(e)))
        assert code == "ValidationException", f"an envelope without {field!r} gave {code!r}"
        assert message == "Parameter Event is not valid.", f"an envelope without {field!r} was refused with {message!r}"

    for field in ("resources", "detail"):
        event = {k: v for k, v in full.items() if k != field}
        resp = ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(event))
        assert resp["Result"] is True, f"an envelope without optional {field!r} did not match: {resp!r}"

    bad_time = dict(full, time="sim2real-not-a-timestamp")
    code, message = _error(lambda: ev.test_event_pattern(EventPattern=pattern, Event=json.dumps(bad_time)))
    assert code == "ValidationException", f"an envelope with an unparseable time gave {code!r}"
    assert message == "Parameter Event is not valid. Reason: Invalid time.", (
        f"an envelope with an unparseable time was refused with {message!r}"
    )

    code, message = _error(lambda: ev.test_event_pattern(EventPattern=pattern, Event="{not json"))
    assert code == "ValidationException", f"an Event that is not JSON gave {code!r}"
    assert message == "Parameter Event is not valid.", f"an Event that is not JSON was refused with {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
