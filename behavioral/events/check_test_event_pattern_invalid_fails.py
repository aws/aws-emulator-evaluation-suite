"""test-event-pattern-invalid-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-invalid-fails"
GROUP = 'test-event-pattern'
SERVICES = ['events']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestEventPattern matches a well-formed pattern, and rejects unparseable JSON, a scalar filter value
    and an empty filter array, each with InvalidEventPatternException and its exact message."""
    ev = ctx.client("events")
    event = json.dumps({
        "id": "11111111-2222-3333-4444-555555555555",
        "version": "0",
        "detail-type": "OrderPlaced",
        "source": "sim2real.orders",
        "account": "123456789012",
        "time": "2024-01-01T00:00:00Z",
        "region": ctx.region,
        "resources": [],
        "detail": {},
    })

    control = ev.test_event_pattern(
        EventPattern=json.dumps({"source": ["sim2real.orders"]}), Event=event
    )
    assert control["Result"] is True, (
        f"positive control failed: a well-formed matching pattern must report Result=True, "
        f"got {control!r}"
    )

    bad_json = "{not valid json"
    scalar = json.dumps({"source": "sim2real.orders"})
    empty = json.dumps({"source": []})
    for pattern, why, expected_message in [
        (
            bad_json,
            "JSON text that does not parse",
            "Event pattern is not valid. Reason: Unexpected character ('n' (code 110)): was "
            "expecting double-quote to start field name\n"
            f" at [Source: (String)\"{bad_json}\"; line: 1, column: 2]",
        ),
        (
            scalar,
            "a filter value that is a bare scalar, not an array",
            "Event pattern is not valid. Reason: \"source\" must be an object or an array\n"
            f" at [Source: (String)\"{scalar}\"; line: 1, column: 13]",
        ),
        (
            empty,
            "a filter value that is an empty array",
            "Event pattern is not valid. Reason: Empty arrays are not allowed\n"
            f" at [Source: (String)\"{empty}\"; line: 1, column: 14]",
        ),
    ]:
        err = _client_error(lambda p=pattern: ev.test_event_pattern(EventPattern=p, Event=event))
        assert err.get("Code") == "InvalidEventPatternException", (
            f"TestEventPattern must reject {why}: expected InvalidEventPatternException, got {err}\n"
            f"  pattern = {pattern}"
        )
        assert err.get("Message") == expected_message, (
            f"TestEventPattern must reject {why} with message {expected_message!r}, got "
            f"{err.get('Message')!r}"
        )


def _client_error(call) -> dict:
    """Run `call` and return the botocore Error dict it raised. An unexpected SUCCESS raises."""
    try:
        result = call()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
