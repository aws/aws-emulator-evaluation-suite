"""list-events-chronological-order-preserved."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-events-chronological-order-preserved"
GROUP = "ordering"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multiple CreateEvent calls for the same actor/session are returned by ListEvents in
    strict reverse creation-time order (newest eventId first): ListEvents has no sort-direction
    parameter, so this is a fixed contract, not an incidental default."""
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")

    mem_name = ("simrealmem" + uuid.uuid4().hex)[:40]
    memory = control.create_memory(
        name=mem_name, eventExpiryDuration=7, tags={"sim2real": CHECK}
    )["memory"]
    memory_id = memory["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    if not _poll_memory_ready(control, memory_id, timeout_s=180):
        raise AssertionError(
            "Memory resource never left CREATING within 180s",
        )

    actor_id = "sim2real-actor"
    session_id = ("simrealsession" + uuid.uuid4().hex)[:60]

    created_event_ids = []
    for i in range(5):
        resp = agentcore.create_event(
            memoryId=memory_id,
            actorId=actor_id,
            sessionId=session_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[
                {"conversational": {"content": {"text": f"sim2real-message-{i}"}, "role": "USER"}}
            ],
        )
        created_event_ids.append(resp["event"]["eventId"])
        time.sleep(1)

    listed = agentcore.list_events(
        memoryId=memory_id, actorId=actor_id, sessionId=session_id, maxResults=100
    )
    listed_ids = [e["eventId"] for e in listed["events"]]

    expected_ids = list(reversed(created_event_ids))
    assert listed_ids == expected_ids, (
        f"expected reverse creation order (newest first) {expected_ids}, got {listed_ids}"
    )


# ===== helpers =====


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
def _poll_memory_ready(control, memory_id: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = control.get_memory(memoryId=memory_id)
        status = resp.get("memory", {}).get("status")
        if status == "ACTIVE":
            return True
        if status == "FAILED":
            raise AssertionError("memory reached terminal status FAILED, expected ACTIVE")
        time.sleep(5)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
