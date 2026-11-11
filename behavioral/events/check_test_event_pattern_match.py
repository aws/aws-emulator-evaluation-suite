"""test-event-pattern-match."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-event-pattern-match"
GROUP = 'test-event-pattern'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """TestEventPattern reports a match when the event satisfies the pattern,
    and reports no match for an otherwise-identical event that does not."""
    ev = ctx.client("events")
    pattern = json.dumps({"source": ["test.source"]})

    def envelope(source: str) -> str:
        return json.dumps(
            {
                "source": source,
                "detail-type": "test",
                "detail": {},
                "region": ctx.region,
                "account": "123456789012",
                "id": "11111111-1111-1111-1111-111111111111",
                "time": "2023-01-01T00:00:00Z",
                "resources": [],
            }
        )

    match_resp = ev.test_event_pattern(EventPattern=pattern, Event=envelope("test.source"))
    assert match_resp["Result"] is True, (
        f"expected Result=True for an event matching the pattern, got {match_resp}"
    )

    mismatch_resp = ev.test_event_pattern(EventPattern=pattern, Event=envelope("other.source"))
    assert mismatch_resp["Result"] is False, (
        f"expected Result=False for an event that does not match the pattern, got {mismatch_resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
