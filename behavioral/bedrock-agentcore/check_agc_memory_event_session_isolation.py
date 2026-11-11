"""agc-memory-event-session-isolation."""
from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agc-memory-event-session-isolation"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """With a sibling session's id, GetEvent and DeleteEvent on an event return
    ResourceNotFoundException ('Unable to find event with id <id>') and the sibling's ListEvents
    never carries it, while a delete in the event's own session removes it.
    """
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_memory(ctx, control)

    # One actor, two sessions: the boundary under test is the session, so everything else about
    # the two events is deliberately identical.
    actor_id = _identifier(ctx, "sim2realactor")
    session_one = _identifier(ctx, "sim2realsessone")
    session_two = _identifier(ctx, "sim2realsesstwo")
    assert session_one != session_two, "the two session ids collided"

    secret_one = f"conversation-one-{session_one}"
    secret_two = f"conversation-two-{session_two}"

    event_one = _create_event(data, memory_id, actor_id, session_one, secret_one)
    event_two = _create_event(data, memory_id, actor_id, session_two, secret_two)
    assert event_one != event_two, f"both CreateEvent calls minted the same id {event_one!r}"

    # Positive controls: each event is readable in its own session, with its own payload. Both
    # sessions work at this moment, so a not-found below is about the pairing and nothing else.
    assert _payload_text(data, memory_id, actor_id, session_one, event_one) == secret_one
    assert _payload_text(data, memory_id, actor_id, session_two, event_two) == secret_two

    # The event id is not a global address: presented under the sibling session it does not exist.
    for session_id, event_id, owner in (
        (session_two, event_one, session_one),
        (session_one, event_two, session_two),
    ):
        code, message = _error(lambda s=session_id, e=event_id: data.get_event(
            memoryId=memory_id, actorId=actor_id, sessionId=s, eventId=e))
        assert code == "ResourceNotFoundException", (
            f"GetEvent served session {owner!r}'s event {event_id!r} to session {session_id!r} "
            f"(got {code!r} instead of ResourceNotFoundException)"
        )
        expected = f"Unable to find event with id {event_id}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Nor does the sibling's listing leak it — neither the id nor, more importantly, the text.
    _assert_listing(data, memory_id, actor_id, session_one, event_one, secret_one,
                    event_two, secret_two)
    _assert_listing(data, memory_id, actor_id, session_two, event_two, secret_two,
                    event_one, secret_one)

    # A cross-session DELETE is refused on the same grounds, and is a no-op rather than a
    # partially applied one: the event is still readable where it does live afterwards.
    delete_code, delete_message = _error(lambda: data.delete_event(
        memoryId=memory_id, actorId=actor_id, sessionId=session_two, eventId=event_one))
    assert delete_code == "ResourceNotFoundException", (
        f"DeleteEvent aimed at session {session_one!r}'s event from session {session_two!r} "
        f"returned {delete_code!r} instead of ResourceNotFoundException"
    )
    expected_delete = f"Event not found with id: {event_one}"
    assert delete_message == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_message!r}"
    )
    assert _payload_text(data, memory_id, actor_id, session_one, event_one) == secret_one, (
        f"the refused cross-session DeleteEvent still damaged event {event_one!r}"
    )

    # Both sessions are genuinely present under this one actor, so every not-found above is
    # session scoping rather than a session (or an actor) that was never there.
    sessions = _all_sessions(data, memory_id, actor_id)
    assert {session_one, session_two} <= sessions, (
        f"ListSessions for actor {actor_id!r} reported {sorted(sessions)!r}, which does not "
        f"contain both {session_one!r} and {session_two!r}"
    )

    # The owning session can delete its own event — the refusal above was about the boundary,
    # not about DeleteEvent being inert.
    data.delete_event(memoryId=memory_id, actorId=actor_id, sessionId=session_one,
                      eventId=event_one)
    gone_code, gone_message = _error(lambda: data.get_event(
        memoryId=memory_id, actorId=actor_id, sessionId=session_one, eventId=event_one))
    assert gone_code == "ResourceNotFoundException", (
        f"GetEvent still answered for an event its own session deleted (got {gone_code!r})"
    )
    expected_gone = f"Unable to find event with id {event_one}"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


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


def _identifier(ctx, prefix):
    """A per-run identifier of only alphanumerics.

    ``ctx.unique_name`` emits hyphens; the memory APIs are strict about their identifier
    patterns, so the same sanitising is applied to every id this check mints.
    """
    return prefix + "".join(c for c in ctx.unique_name("x") if c.isalnum())[:32]


def _create_memory(ctx, control) -> str:
    """Create a short-lived memory, register its teardown, and wait out CREATING.

    No memory strategy is configured: this check is about event addressing, and the extraction
    pipeline a strategy would add is both irrelevant here and slow.
    """
    name = "sim2realmem" + "".join(c for c in ctx.unique_name("x") if c.isalnum())[:36]
    created = control.create_memory(name=name, eventExpiryDuration=7)
    memory_id = created["memory"]["arn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    status = created["memory"].get("status")
    deadline = time.monotonic() + 240.0
    while status == "CREATING" and time.monotonic() < deadline:
        time.sleep(5.0)
        status = control.get_memory(memoryId=memory_id)["memory"].get("status")
    assert status == "ACTIVE", (
        f"memory {memory_id!r} reported status {status!r} rather than ACTIVE within 240s; "
        f"no event can be written to it"
    )
    return memory_id


def _create_event(data, memory_id, actor_id, session_id, text) -> str:
    """The minted eventId for one conversational turn.

    A memory can answer ACTIVE from the control plane slightly before its data plane accepts
    writes; that gap is retried through, and anything else is raised.
    """
    deadline = time.monotonic() + 90.0
    while True:
        try:
            response = data.create_event(
                memoryId=memory_id,
                actorId=actor_id,
                sessionId=session_id,
                eventTimestamp=_dt.datetime.now(_dt.timezone.utc),
                payload=[{"conversational": {"role": "USER", "content": {"text": text}}}],
            )
            break
        except Exception as exc:  # noqa: BLE001 - narrowed by the message test below
            if "not active" in str(exc) and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    event = response["event"]
    assert event["sessionId"] == session_id, (
        f"CreateEvent echoed sessionId {event['sessionId']!r}, not {session_id!r}"
    )
    return event["eventId"]


def _payload_text(data, memory_id, actor_id, session_id, event_id):
    """The single conversational text GetEvent returns for *event_id* in *session_id*."""
    event = data.get_event(
        memoryId=memory_id, actorId=actor_id, sessionId=session_id, eventId=event_id)["event"]
    assert event["eventId"] == event_id, (
        f"GetEvent for {event_id!r} answered with {event['eventId']!r}"
    )
    payload = event["payload"]
    assert len(payload) == 1, f"expected one payload block on {event_id!r}, got {payload!r}"
    return payload[0]["conversational"]["content"]["text"]


def _assert_listing(data, memory_id, actor_id, session_id, own_event, own_text,
                    other_event, other_text):
    """ListEvents for *session_id* holds its own event and no trace of the sibling's."""
    events = []
    token = None
    while True:
        kwargs = {"memoryId": memory_id, "actorId": actor_id, "sessionId": session_id,
                  "includePayloads": True}
        if token:
            kwargs["nextToken"] = token
        page = data.list_events(**kwargs)
        events.extend(page.get("events") or [])
        token = page.get("nextToken")
        if not token:
            break

    ids = [event["eventId"] for event in events]
    assert ids == [own_event], (
        f"ListEvents for session {session_id!r} returned {ids!r}, expected exactly [{own_event!r}]"
    )
    texts = [
        block["conversational"]["content"]["text"]
        for event in events for block in event.get("payload") or []
        if "conversational" in block
    ]
    assert texts == [own_text], (
        f"ListEvents for session {session_id!r} returned payload texts {texts!r}, "
        f"expected exactly [{own_text!r}]"
    )
    assert other_event not in ids and other_text not in texts, (
        f"session {session_id!r} can see the other session's event: ids={ids!r} texts={texts!r}"
    )


def _all_sessions(data, memory_id, actor_id):
    """Every sessionId ListSessions reports for *actor_id*, across pages."""
    found = set()
    token = None
    while True:
        kwargs = {"memoryId": memory_id, "actorId": actor_id}
        if token:
            kwargs["nextToken"] = token
        page = data.list_sessions(**kwargs)
        found.update(s["sessionId"] for s in page.get("sessionSummaries") or [])
        token = page.get("nextToken")
        if not token:
            return found


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected an AWS error, but the call SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
