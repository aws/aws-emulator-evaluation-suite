"""list-events-include-payloads-false-omits-only-the-projection."""

# CreateEvent's own response carries no `payload` even though the Event shape marks it required,
# so storage is proven by the independent ListEvents(includePayloads=True) and GetEvent reads.
from __future__ import annotations

import datetime as _dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-events-include-payloads-false-omits-only-the-projection"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """includePayloads changes only the projection, never the selection: both ListEvents
    responses name the identical events, the False response carries no payload and none of the
    payload text, and GetEvent still returns the payload for the same events."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_active_memory(ctx, control)

    tenant = ctx.unique_name("").replace("-", "")
    actor_id = f"simparitypayload{tenant}"
    session_id = f"simparitysession{tenant}"
    text_one = f"first-payload-{tenant}"
    text_two = f"second-payload-{tenant}"

    event_one = _create_event(data, memory_id, actor_id, session_id, text_one)
    event_two = _create_event(data, memory_id, actor_id, session_id, text_two)
    expected_ids = {event_one, event_two}

    # POSITIVE CONTROL first: with payloads requested, both events and both texts are there. Any
    # absence asserted below is therefore absence-despite-storage.
    with_payloads = _poll_until(
        lambda: data.list_events(
            memoryId=memory_id,
            actorId=actor_id,
            sessionId=session_id,
            maxResults=100,
            includePayloads=True,
        )["events"],
        lambda events: {e["eventId"] for e in events} == expected_ids,
        timeout_s=30.0,
        interval_s=3.0,
        description="ListEvents(includePayloads=True) reported both created events",
    )
    with_blob = json.dumps(with_payloads, default=str)
    for text in (text_one, text_two):
        assert text in with_blob, (
            f"ListEvents(includePayloads=True) did not carry the payload text {text!r}: "
            f"{with_blob[:400]!r}"
        )
    for event in with_payloads:
        assert event["payload"], (
            f"event {event['eventId']!r} came back from includePayloads=True with an empty "
            f"payload: {event!r}"
        )

    # The discriminator, in the same instant: exactly one request field changes.
    without_payloads = data.list_events(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        maxResults=100,
        includePayloads=False,
    )["events"]
    without_ids = {e["eventId"] for e in without_payloads}
    assert without_ids == expected_ids, (
        f"ListEvents(includePayloads=False) selected {sorted(without_ids)!r}, expected the same "
        f"events as the True projection, {sorted(expected_ids)!r}. The flag governs the "
        "projection, not which events are returned"
    )
    for event in without_payloads:
        # Correct `.get(..., [])` polarity: the empty default feeds `assert not`, so a target that
        # omits the key and a target that returns an empty list both satisfy the contract, while a
        # target that echoes the payload anyway fails.
        assert not event.get("payload", []), (
            f"event {event['eventId']!r} still carried a payload when includePayloads=False: "
            f"{event.get('payload')!r}"
        )
    without_blob = json.dumps(without_payloads, default=str)
    for text in (text_one, text_two):
        assert text not in without_blob, (
            f"the includePayloads=False response leaked the payload text {text!r} somewhere "
            f"outside the payload member: {without_blob[:400]!r}"
        )

    # Order and identity are preserved between the two projections, not merely the id SET — a
    # target that reshuffles when payloads are dropped is diverging.
    assert [e["eventId"] for e in without_payloads] == [
        e["eventId"] for e in with_payloads
    ], (
        "the two projections disagree on event ORDER: "
        f"{[e['eventId'] for e in without_payloads]!r} vs "
        f"{[e['eventId'] for e in with_payloads]!r}"
    )

    # Terminal read at the destination through a DIFFERENT operation: GetEvent still has the
    # payload, so the False projection omitted it rather than the store dropping it.
    for event_id, text in ((event_one, text_one), (event_two, text_two)):
        got = data.get_event(
            memoryId=memory_id, actorId=actor_id, sessionId=session_id, eventId=event_id
        )["event"]
        assert got["eventId"] == event_id, (
            f"GetEvent returned eventId {got['eventId']!r}, expected {event_id!r}"
        )
        assert got["payload"], (
            f"GetEvent returned no payload for {event_id!r}; the event text was never stored, "
            "which is a different (worse) defect than omitting it from a list projection"
        )
        got_blob = json.dumps(got["payload"], default=str)
        assert text in got_blob, (
            f"GetEvent's payload for {event_id!r} does not contain {text!r}: {got_blob[:300]!r}"
        )



# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_memory(control, memory_id):
    _ac_delete_and_wait(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda: control.delete_memory(memoryId=memory_id),
        what=f"memory {memory_id}",
    )


def _create_active_memory(ctx, control) -> str:
    """Create a uniquely named, tagged memory, register teardown, and wait for ACTIVE with a
    bounded poll that RAISES on timeout. No strategy: this check needs short-term storage only,
    so it does not depend on model entitlement."""
    name = "simparitypayload" + ctx.unique_name("").replace("-", "")[:20]
    resp = control.create_memory(
        name=name,
        eventExpiryDuration=7,
        tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
    )
    memory = resp["memory"]
    memory_id = memory.get("id") or memory["arn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    status = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "FAILED"),
        # 240s: a new memory with a strategy can stay CREATING for well over 90s.
        timeout_s=240.0,
        interval_s=5.0,
        description=f"memory {memory_id} left CREATING",
    )
    assert status == "ACTIVE", (
        f"memory {memory_id} reached terminal status {status!r}, expected 'ACTIVE'"
    )
    return memory_id


def _create_event(data, memory_id, actor_id, session_id, text) -> str:
    event = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=_dt.datetime.now(_dt.timezone.utc),
        payload=[{"conversational": {"content": {"text": text}, "role": "USER"}}],
    )["event"]
    # CreateEvent's own response never echoes the payload back (measured on real AWS: the event
    # carries only memoryId/actorId/sessionId/eventId/eventTimestamp/branch), so storage is proven
    # below by the independent ListEvents(includePayloads=True) and GetEvent reads, not here.
    return event["eventId"]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
