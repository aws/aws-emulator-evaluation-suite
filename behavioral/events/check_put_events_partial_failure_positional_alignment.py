"""put-events-partial-failure-positional-alignment."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-partial-failure-positional-alignment"
GROUP = 'put-events'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A mixed PutEvents batch returns per-entry results aligned to the request (EventId on valid,
    InvalidArgument on invalid entries), an 11-entry batch is refused whole with
    ValidationException, and an entry on a rule-less bus is still accepted with an EventId.
    """
    ev = ctx.client("events")

    # A dedicated bus with no rules, so nothing is delivered and default-bus rules cannot interfere.
    bus = ctx.unique_name("sim2real-behav-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    assert ev.list_rules(EventBusName=bus).get("Rules", []) == [], (
        f"a freshly created bus {bus!r} must have no rules"
    )

    # Invalid entries are non-adjacent and neither first nor last, so a compacted or reordered
    # response cannot pass.
    good = {"Source": "sim2real.orders", "DetailType": "OrderPlaced",
            "Detail": json.dumps({"n": 0}), "EventBusName": bus}
    entries = [
        dict(good, Detail=json.dumps({"n": 0})),
        # index 1: no Source
        {"DetailType": "OrderPlaced", "Detail": json.dumps({"n": 1}), "EventBusName": bus},
        dict(good, Detail=json.dumps({"n": 2})),
        # index 3: no DetailType
        {"Source": "sim2real.orders", "Detail": json.dumps({"n": 3}), "EventBusName": bus},
        dict(good, Detail=json.dumps({"n": 4})),
    ]
    resp = ev.put_events(Entries=entries)
    results = resp["Entries"]

    assert len(results) == len(entries), (
        f"PutEvents must return one result per request entry: sent {len(entries)}, got "
        f"{len(results)} -- {json.dumps(results, default=str)}"
    )
    assert resp["FailedEntryCount"] == 2, (
        f"expected FailedEntryCount=2, got {resp['FailedEntryCount']} -- "
        f"{json.dumps(results, default=str)}"
    )

    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    for i in (0, 2, 4):
        entry = results[i]
        assert "ErrorCode" not in entry, (
            f"entry {i} was valid but came back with ErrorCode={entry.get('ErrorCode')!r}: "
            f"{json.dumps(entry, default=str)}"
        )
        event_id = entry.get("EventId")
        assert isinstance(event_id, str) and uuid_re.match(event_id), (
            f"entry {i} was valid so it must carry a UUID EventId, got {event_id!r}"
        )

    failure_by_index = {
        1: ("Source", "an entry with no Source"),
        3: ("DetailType", "an entry with no DetailType"),
    }
    for i, (parameter, why) in failure_by_index.items():
        entry = results[i]
        assert entry.get("ErrorCode") == "InvalidArgument", (
            f"index {i} is {why}, so it must fail with ErrorCode=InvalidArgument, got "
            f"{entry.get('ErrorCode')!r}: {json.dumps(entry, default=str)}"
        )
        message = entry.get("ErrorMessage") or ""
        assert parameter in message, (
            f"index {i} is {why}, so its ErrorMessage must name the offending parameter "
            f"{parameter!r}; got {message!r}. A per-entry error that does not identify the field "
            f"is not actionable for the caller."
        )
        assert "EventId" not in entry, (
            f"index {i} failed, so it must NOT carry an EventId; got {entry.get('EventId')!r}. "
            f"An EventId on a failed entry makes the failure invisible to a caller that keys off "
            f"EventId presence."
        )

    # PutEvents is not idempotent: a re-send keeps the shape but mints fresh EventIds.
    resp2 = ev.put_events(Entries=entries)
    assert resp2["FailedEntryCount"] == 2, (
        f"the second identical PutEvents returned FailedEntryCount={resp2['FailedEntryCount']}"
    )
    assert [("ErrorCode" in e) for e in resp2["Entries"]] == [False, True, False, True, False], (
        f"the second call's failure positions differ from the first: "
        f"{json.dumps(resp2['Entries'], default=str)}"
    )
    first_ids = [results[i]["EventId"] for i in (0, 2, 4)]
    second_ids = [resp2["Entries"][i]["EventId"] for i in (0, 2, 4)]
    assert set(first_ids).isdisjoint(second_ids), (
        f"PutEvents is not idempotent, so a re-send must mint fresh EventIds; got overlap between "
        f"{first_ids} and {second_ids}"
    )

    # A limit violation is a whole-request refusal, not a partial failure.
    oversized = [dict(good, Detail=json.dumps({"n": n})) for n in range(11)]
    code, message = _error(lambda: ev.put_events(Entries=oversized))
    assert code == "ValidationException", (
        f"PutEvents must refuse an 11-entry batch outright (the modeled maximum is 10): expected "
        f"ValidationException, got {code}. A partial acceptance here would be the worst outcome -- "
        f"the caller cannot tell which 10 of its 11 events survived."
    )
    # The message echoes every entry through a server-side type name: assert its fixed head and end.
    assert message.startswith("1 validation error detected: Value '["), message
    assert message.endswith(
        "]' at 'entries' failed to satisfy constraint: Member must have length less than or equal to 10"
    ), message

    # An EventId means accepted, not delivered: this bus has no rules.
    lone = ev.put_events(Entries=[dict(good, Detail=json.dumps({"n": "no-rules"}))])
    assert lone["FailedEntryCount"] == 0, (
        f"a well-formed entry on a bus with no rules must still be accepted, got "
        f"{json.dumps(lone, default=str)}"
    )
    assert uuid_re.match(lone["Entries"][0]["EventId"] or ""), (
        f"an accepted entry on a rule-less bus must still be assigned an EventId, got "
        f"{lone['Entries'][0].get('EventId')!r}"
    )
    assert ev.list_rules(EventBusName=bus).get("Rules", []) == [], (
        "PutEvents must not create rules on the target bus"
    )


def _error(call) -> tuple[str, str]:
    """Run `call` and return the AWS error (code, message) it raised; an unexpected success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Error.Code>"), err.get("Message", "")
    raise AssertionError(
        f"expected real AWS to refuse this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
