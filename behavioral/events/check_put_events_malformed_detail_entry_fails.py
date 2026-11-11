"""put-events-malformed-detail-entry-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "put-events-malformed-detail-entry-fails"
GROUP = 'put-events'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutEvents entry whose Detail is not valid JSON fails at the entry level with
    MalformedDetail and no EventId, while a well-formed entry in the same batch succeeds."""
    ev = ctx.client("events")
    source = ctx.unique_name("sim2real.behav.source.")
    resp = ev.put_events(
        Entries=[
            {"Source": source, "DetailType": "Good", "Detail": json.dumps({"ok": True})},
            {"Source": source, "DetailType": "test", "Detail": "{not json"},
        ]
    )
    assert resp["FailedEntryCount"] == 1, f"expected exactly 1 failed entry, got {resp}"
    entries = resp["Entries"]
    assert len(entries) == 2, f"expected one result per submitted entry, got {resp}"
    good, bad = entries[0], entries[1]
    assert "EventId" in good and "ErrorCode" not in good, (
        f"positive control (well-formed) entry unexpectedly failed: {good}"
    )
    assert (bad.get("ErrorCode"), bad.get("ErrorMessage")) == (
        "MalformedDetail", "Detail is malformed."
    ), f"expected MalformedDetail, got {bad}"
    assert "EventId" not in bad, f"malformed entry must not carry an EventId: {bad}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
