"""empty-vs-absent-field-preserved."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-vs-absent-field-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateEvent distinguishes an explicit empty-string metadata value from an omitted key."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_plain_memory(ctx, control)
    actor_id = ctx.unique_name("actor")
    session_id = ctx.unique_name("sess")

    created = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=datetime.now(timezone.utc),
        payload=[{"conversational": {"role": "USER", "content": {"text": "hello"}}}],
        # "present_empty" is explicitly set to the empty string.
        metadata={"present_empty": {"stringValue": ""}},
    )
    event_id = created["event"]["eventId"]
    ctx.on_cleanup(
        lambda: data.delete_event(
            memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
        )
    )

    # The `metadata` parameter itself is optional; this sibling event omits it entirely,
    # which is the actual "absent" side of the contract (a fabricated key that nothing ever
    # sent can never legitimately appear, so checking for it proves nothing).
    no_metadata_created = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=datetime.now(timezone.utc),
        payload=[{"conversational": {"role": "USER", "content": {"text": "hi"}}}],
    )
    no_metadata_event_id = no_metadata_created["event"]["eventId"]
    ctx.on_cleanup(
        lambda: data.delete_event(
            memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=no_metadata_event_id
        )
    )

    fetched = data.get_event(
        memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
    )
    metadata = fetched["event"].get("metadata", {})
    assert "present_empty" in metadata, "explicit empty-string field was dropped on read-back"
    assert metadata["present_empty"]["stringValue"] == ""
    assert set(metadata.keys()) == {"present_empty"}, (
        f"expected only the sent key back, got {sorted(metadata)}"
    )

    fetched_no_metadata = data.get_event(
        memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=no_metadata_event_id
    )
    no_metadata_map = fetched_no_metadata["event"].get("metadata", {})
    assert no_metadata_map == {}, (
        f"event created with metadata omitted came back with metadata={no_metadata_map!r}"
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

def _create_plain_memory(ctx, control):
    raw = ctx.unique_name("sim2realmemplain")
    name = "".join(c for c in raw if c.isalnum() or c == "_")[:48]
    if not name or not name[0].isalpha():
        name = "a" + name
    created = control.create_memory(
        name=name,
        description="sim2real behavioral fidelity check: short-term memory for CreateEvent",
        eventExpiryDuration=7,
        tags={"sim2real": "empty-vs-absent-field-preserved"},
    )
    memory_id = created["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))
    _wait_for_memory_active(control, memory_id, timeout_s=420.0, interval_s=10.0)
    return memory_id


def _wait_for_memory_active(control, memory_id, *, timeout_s=420.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = control.get_memory(memoryId=memory_id)
        memory = resp["memory"]
        status = memory.get("status")
        if status == "ACTIVE":
            return memory
        if status in ("CREATE_FAILED", "FAILED"):
            raise AssertionError(f"memory {memory_id} entered terminal failure status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"memory {memory_id} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
