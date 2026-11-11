"""put-events-detail-that-is-json-but-not-an-object-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-events-detail-that-is-json-but-not-an-object-rejected"
GROUP = 'put-events'
SERVICES = ['events']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one PutEvents batch, array, number and string Details each fail in place with
    MalformedDetail "Detail is malformed." while object and empty-object Details get EventIds;
    FailedEntryCount is 3.
    """
    ev = ctx.client("events")
    source = ctx.unique_name("sim2real.behav.detail.")
    details = [
        json.dumps({"ok": True}),
        json.dumps([1, 2]),
        json.dumps(5),
        json.dumps("text"),
        json.dumps({}),
    ]
    resp = ev.put_events(Entries=[
        {"Source": source, "DetailType": "Sim2realDetailShape", "Detail": d} for d in details
    ])
    entries = resp["Entries"]
    assert len(entries) == len(details), f"PutEvents returned {len(entries)} entries for {len(details)} sent"
    assert resp["FailedEntryCount"] == 3, f"FailedEntryCount is {resp['FailedEntryCount']!r}, expected 3"

    for i in (0, 4):
        assert "EventId" in entries[i] and "ErrorCode" not in entries[i], (
            f"entry {i} with object Detail {details[i]!r} was not accepted: {entries[i]!r}"
        )
    for i in (1, 2, 3):
        assert entries[i].get("ErrorCode") == "MalformedDetail", (
            f"entry {i} with non-object Detail {details[i]!r} gave {entries[i]!r}, expected MalformedDetail"
        )
        assert entries[i].get("ErrorMessage") == "Detail is malformed.", (
            f"entry {i} with non-object Detail {details[i]!r} gave message {entries[i].get('ErrorMessage')!r}"
        )
        assert "EventId" not in entries[i], f"failed entry {i} still carries an EventId: {entries[i]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
