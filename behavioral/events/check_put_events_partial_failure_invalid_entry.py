"""put-events-partial-failure-invalid-entry."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-events-partial-failure-invalid-entry"
GROUP = 'put-events'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents reports per-entry failures (missing required fields) while still succeeding for well-formed entries in the same batch: the good entry gets an EventId, the bad entry gets an ErrorCode, and FailedEntryCount is exactly 1."""
    ev = ctx.client("events")
    source = ctx.unique_name("sim2real.behav.source.")
    resp = ev.put_events(
        Entries=[
            {"Source": source, "DetailType": "Good", "Detail": json.dumps({"ok": True})},
            {"DetailType": "Missing Source", "Detail": json.dumps({"ok": False})},
        ]
    )
    assert resp["FailedEntryCount"] == 1, f"expected exactly 1 failed entry, got {resp}"
    entries = resp["Entries"]
    assert len(entries) == 2, (
        f"PutEvents must return one result per request entry: sent 2, got {len(entries)} -- {entries}"
    )
    assert "EventId" in entries[0] and "ErrorCode" not in entries[0], (
        f"entry 0 was well-formed so it must carry an EventId and no ErrorCode, got {entries[0]}"
    )
    assert "ErrorCode" in entries[1] and "EventId" not in entries[1], (
        f"entry 1 was missing Source so it must carry an ErrorCode and no EventId, got {entries[1]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
