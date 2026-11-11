"""list-sessions-and-actors-scoped-to-their-own-actor."""
from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-sessions-and-actors-scoped-to-their-own-actor"
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
    """Sessions are partitioned by actor: ListSessions for one actor returns exactly that
    actor's sessions and never the other actor's, ListActors reports both, and ListEvents for a
    session returns only that session's events."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_active_memory(ctx, control)

    tenant = ctx.unique_name("").replace("-", "")
    actor_alpha = f"simparityalpha{tenant}"
    actor_beta = f"simparitybeta{tenant}"
    alpha_s1 = f"alphaone{tenant}"
    alpha_s2 = f"alphatwo{tenant}"
    beta_s1 = f"betaone{tenant}"

    # The memory is brand new, so both listings start empty. This is the baseline that makes
    # the exact-set assertions below meaningful rather than "our rows happen to be in there".
    assert _actor_ids(data, memory_id) == set(), (
        "a freshly created memory already reports actors: "
        f"{sorted(_actor_ids(data, memory_id))!r}"
    )

    # Three events, back to back, so both actors are populated in the same instant: the twin
    # control group. A target keeping one undifferentiated session bucket cannot pass the
    # two scoping legs below.
    event_alpha_s1 = _create_event(data, memory_id, actor_alpha, alpha_s1, "alpha first")
    _create_event(data, memory_id, actor_alpha, alpha_s2, "alpha second")
    event_beta_s1 = _create_event(data, memory_id, actor_beta, beta_s1, "beta first")

    # Positive legs first: both actors' sessions really are listable.
    alpha_sessions = _poll_until(
        lambda: _session_ids(data, memory_id, actor_alpha),
        lambda ids: ids == {alpha_s1, alpha_s2},
        timeout_s=30.0,
        interval_s=3.0,
        description=f"ListSessions(actorId={actor_alpha}) reported both of its sessions",
    )
    beta_sessions = _poll_until(
        lambda: _session_ids(data, memory_id, actor_beta),
        lambda ids: ids == {beta_s1},
        timeout_s=30.0,
        interval_s=3.0,
        description=f"ListSessions(actorId={actor_beta}) reported its session",
    )

    # The discriminator: each actor's listing is exactly its own, on reads taken after BOTH
    # actors are demonstrably present, so an absence is absence-despite-presence.
    assert alpha_sessions == {alpha_s1, alpha_s2}, (
        f"ListSessions(actorId={actor_alpha!r}) returned {sorted(alpha_sessions)!r}, expected "
        f"exactly {sorted({alpha_s1, alpha_s2})!r}"
    )
    assert beta_s1 not in alpha_sessions, (
        f"actor {actor_alpha!r} can see actor {actor_beta!r}'s session {beta_s1!r}: "
        f"{sorted(alpha_sessions)!r}. Sessions are keyed by actor in the modelled URI, so a "
        "shared bucket is a cross-actor leak"
    )
    assert beta_sessions == {beta_s1}, (
        f"ListSessions(actorId={actor_beta!r}) returned {sorted(beta_sessions)!r}, expected "
        f"exactly [{beta_s1!r}]"
    )
    assert not ({alpha_s1, alpha_s2} & beta_sessions), (
        f"actor {actor_beta!r} can see actor {actor_alpha!r}'s sessions: "
        f"{sorted(beta_sessions)!r}"
    )

    # ListActors is the union side of the same partition: both actors, and nothing else.
    actors = _poll_until(
        lambda: _actor_ids(data, memory_id),
        lambda ids: {actor_alpha, actor_beta} <= ids,
        timeout_s=30.0,
        interval_s=3.0,
        description="ListActors reported both actors that have events",
    )
    assert actors == {actor_alpha, actor_beta}, (
        f"ListActors returned {sorted(actors)!r}, expected exactly "
        f"{sorted({actor_alpha, actor_beta})!r} — the two actors this check created and no others"
    )

    # Terminal read at the destination through a different operation from the CreateEvent
    # mutations: ListEvents, scoped to one (actor, session) pair, returns that pair's event and
    # neither of the other two.
    beta_events = data.list_events(
        memoryId=memory_id,
        actorId=actor_beta,
        sessionId=beta_s1,
        maxResults=100,
        includePayloads=False,
    )["events"]
    beta_event_ids = {e["eventId"] for e in beta_events}
    assert beta_event_ids == {event_beta_s1}, (
        f"ListEvents(actor={actor_beta!r}, session={beta_s1!r}) returned "
        f"{sorted(beta_event_ids)!r}, expected exactly [{event_beta_s1!r}]"
    )
    assert event_alpha_s1 not in beta_event_ids, (
        f"actor {actor_beta!r}'s session listing contains actor {actor_alpha!r}'s event "
        f"{event_alpha_s1!r}"
    )
    for event in beta_events:
        assert event["actorId"] == actor_beta, (
            f"event {event['eventId']!r} returned under actor {actor_beta!r} reports "
            f"actorId {event['actorId']!r}"
        )
        assert event["sessionId"] == beta_s1, (
            f"event {event['eventId']!r} returned under session {beta_s1!r} reports "
            f"sessionId {event['sessionId']!r}"
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
    name = "simparityactors" + ctx.unique_name("").replace("-", "")[:20]
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
    resp = data.create_event(
        memoryId=memory_id,
        actorId=actor_id,
        sessionId=session_id,
        eventTimestamp=_dt.datetime.now(_dt.timezone.utc),
        payload=[{"conversational": {"content": {"text": text}, "role": "USER"}}],
    )
    event = resp["event"]
    assert event["actorId"] == actor_id, (
        f"CreateEvent echoed actorId {event['actorId']!r}, expected {actor_id!r}"
    )
    assert event["sessionId"] == session_id, (
        f"CreateEvent echoed sessionId {event['sessionId']!r}, expected {session_id!r}"
    )
    return event["eventId"]


def _session_ids(data, memory_id, actor_id) -> set[str]:
    """Every sessionId ListSessions reports for one actor. `sessionSummaries` is REQUIRED in the
    output shape, so it is hard-subscripted rather than defaulted."""
    ids: set[str] = set()
    token = None
    for _ in range(20):
        params = {"memoryId": memory_id, "actorId": actor_id, "maxResults": 100}
        if token:
            params["nextToken"] = token
        resp = data.list_sessions(**params)
        ids.update(s["sessionId"] for s in resp["sessionSummaries"])
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(
        f"ListSessions(actorId={actor_id!r}) did not stop paginating after 20 pages "
        f"({len(ids)} ids)"
    )


def _actor_ids(data, memory_id) -> set[str]:
    """Every actorId ListActors reports. `actorSummaries` is REQUIRED, so hard-subscripted."""
    ids: set[str] = set()
    token = None
    for _ in range(20):
        params = {"memoryId": memory_id, "maxResults": 100}
        if token:
            params["nextToken"] = token
        resp = data.list_actors(**params)
        ids.update(a["actorId"] for a in resp["actorSummaries"])
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(f"ListActors did not stop paginating after 20 pages ({len(ids)} ids)")


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
