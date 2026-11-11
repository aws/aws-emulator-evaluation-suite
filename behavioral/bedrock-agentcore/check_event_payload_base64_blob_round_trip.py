"""event-payload-base64-blob-round-trip."""
from __future__ import annotations

import base64
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-payload-base64-blob-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A binary blob payload written via CreateEvent comes back byte-identical from GetEvent."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_plain_memory(ctx, control)
    actor_id = ctx.unique_name("actor")
    session_id = ctx.unique_name("sess")

    # Exercise every byte value including NUL, high bytes, and padding-sensitive lengths.
    blob_bytes = bytes(range(256)) + b"\x00\x00\x01"
    blob_b64 = base64.b64encode(blob_bytes).decode("ascii")

    created = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=datetime.now(timezone.utc),
        payload=[{"blob": blob_b64}],
    )
    event_id = created["event"]["eventId"]
    ctx.on_cleanup(
        lambda: data.delete_event(
            memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
        )
    )

    fetched = data.get_event(
        memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
    )
    payload = fetched["event"]["payload"]
    assert len(payload) == 1, f"expected exactly one payload entry, got {len(payload)}: {payload!r}"
    round_tripped_b64 = payload[0]["blob"]
    assert round_tripped_b64 == blob_b64, (
        f"base64 payload changed across the round trip: sent {blob_b64!r}, got {round_tripped_b64!r}"
    )
    assert base64.b64decode(round_tripped_b64) == blob_bytes, (
        "decoded bytes no longer match the original 259-byte blob after the round trip"
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
        tags={"Sim2RealOwner": "behavioral-suite"},
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
