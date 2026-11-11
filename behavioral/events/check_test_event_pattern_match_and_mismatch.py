"""test-event-pattern-match-and-mismatch."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-match-and-mismatch"
GROUP = 'test-event-pattern'
SERVICES = ['events']


def _error(fn):
    """Call fn() and return (Code, Message) of the ClientError it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the incomplete envelope to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestEventPattern returns Result=True for a matching event and False for a non-matching one;
    an incomplete event envelope is rejected with ValidationException."""
    ev = ctx.client("events")
    bus_arn = ev.describe_event_bus(Name="default")["Arn"]
    _, _, _, region, account, _ = bus_arn.split(":", 5)
    pattern = json.dumps({"source": ["evb.match.source"]})

    def envelope(source: str) -> str:
        return json.dumps(
            {
                "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "detail-type": "BehavioralCheck",
                "source": source,
                "account": account,
                "time": "2024-01-01T00:00:00Z",
                "region": region,
                "resources": [],
                "detail": {"k": "v"},
            }
        )

    match_resp = ev.test_event_pattern(
        EventPattern=pattern, Event=envelope("evb.match.source")
    )
    assert match_resp["Result"] is True, f"expected Result=True, got {match_resp}"

    mismatch_resp = ev.test_event_pattern(
        EventPattern=pattern, Event=envelope("evb.other.source")
    )
    assert mismatch_resp["Result"] is False, f"expected Result=False, got {mismatch_resp}"

    # An incomplete envelope is a validation error, not a silent False.
    code, message = _error(
        lambda: ev.test_event_pattern(
            EventPattern=pattern,
            Event=json.dumps({"source": "evb.match.source", "detail": {}}),
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an incomplete event envelope, got {code}"
    )
    assert message == "Parameter Event is not valid.", (
        f"incomplete event envelope refused with message {message!r}, "
        "expected 'Parameter Event is not valid.'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
