"""metadata-pattern-violation-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metadata-pattern-violation-rejected"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateEvent with a '#' in a metadata stringValue is refused with ValidationException and the
    exact pattern message and creates no event, while a compliant value in the same session is
    stored and read back by GetEvent.
    """
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_plain_memory(ctx, control)
    actor_id = ctx.unique_name("actor")
    session_id = ctx.unique_name("sess")

    def _bad_create():
        data.create_event(
            memoryId=memory_id,
            actorId=actor_id,
            sessionId=session_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"conversational": {"role": "USER", "content": {"text": "hello"}}}],
            metadata={"channel": {"stringValue": "web#chat"}},
        )

    code, message = _error(_bad_create)
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'metadata.channel.member.stringValue' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9\\s._:/=+@-]*"
    ), f"expected the exact metadata pattern message, got {message!r}"

    # Effect absent: the rejected call must not have created anything in this session.
    listed = data.list_events(memoryId=memory_id, actorId=actor_id, sessionId=session_id)
    assert listed["events"] == [], f"expected no events, found {listed['events']}"

    # Positive control: the same session accepts a compliant metadata value.
    created = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=datetime.now(timezone.utc),
        payload=[{"conversational": {"role": "USER", "content": {"text": "hello"}}}],
        metadata={"channel": {"stringValue": "web-chat"}},
    )
    event_id = created["event"]["eventId"]
    ctx.on_cleanup(
        lambda: data.delete_event(
            memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
        )
    )

    # Terminal read: an independent GetEvent, not the CreateEvent response itself.
    fetched = data.get_event(
        memoryId=memory_id, sessionId=session_id, actorId=actor_id, eventId=event_id
    )
    fetched_value = fetched["event"]["metadata"]["channel"]["stringValue"]
    assert fetched_value == "web-chat", (
        f"expected metadata channel 'web-chat' on independent read, got {fetched_value!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out the transitional status and then for ResourceNotFoundException.
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

def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_plain_memory(ctx, control):
    raw = ctx.unique_name("sim2realmemplain")
    name = "".join(c for c in raw if c.isalnum() or c == "_")[:48]
    if not name or not name[0].isalpha():
        name = "a" + name
    created = control.create_memory(
        name=name,
        description="sim2real behavioral fidelity check: short-term memory for CreateEvent",
        eventExpiryDuration=7,
        tags={"sim2real-check": CHECK},
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
