"""update-session-optimistic-lock-conflict."""
from __future__ import annotations

import threading
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-session-optimistic-lock-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateSession calls on an ACTIVE session leave exactly one racer's metadata (any
    loser gets ConflictException); after EndSession, UpdateSession gets ConflictException with the
    exact message and the metadata stays."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "sim2real-check"})["sessionId"]
    ctx.on_cleanup(lambda: _cleanup_session(ctx, session_id))

    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def _update(tag: str) -> None:
        barrier.wait()
        try:
            resp = client.update_session(
                sessionIdentifier=session_id,
                sessionMetadata={"racer": tag},
            )
            results[tag] = ("ok", resp)
        except Exception as exc:  # noqa: BLE001
            results[tag] = ("error", _error_code(exc))

    threads = [threading.Thread(target=_update, args=(tag,)) for tag in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert set(results) == {"a", "b"}, (
        f"expected both racers to report an outcome within the join timeout, got {results!r}"
    )
    outcomes = {tag: results[tag][0] for tag in ("a", "b")}
    successes = [tag for tag, kind in outcomes.items() if kind == "ok"]
    failures = [tag for tag, kind in outcomes.items() if kind == "error"]

    # every non-ok outcome observed on a still-ACTIVE session must be the
    # documented conflict code -- never a 5xx or something unrelated.
    for tag in failures:
        assert results[tag][1] == "ConflictException", (
            f"racer {tag} failed with unexpected code {results[tag][1]!r}, "
            f"outcomes={outcomes}"
        )
    assert len(successes) >= 1, f"expected at least one writer to win, got outcomes={outcomes}"

    # no data corruption: whichever racer(s) won, the persisted metadata is
    # exactly one racer's full payload, never a merge of both racers' keys.
    session = client.get_session(sessionIdentifier=session_id)
    assert session["sessionMetadata"] in ({"racer": "a"}, {"racer": "b"}), (
        f"persisted metadata is neither racer's clean payload: {session['sessionMetadata']}"
    )
    assert session["sessionStatus"] == "ACTIVE"

    # positive control, in the same file: a normal (non-racing) update
    # against the same still-ACTIVE session succeeds cleanly.
    control = client.update_session(
        sessionIdentifier=session_id, sessionMetadata={"racer": "control"}
    )
    assert control["sessionStatus"] == "ACTIVE"
    after_control = client.get_session(sessionIdentifier=session_id)
    assert after_control["sessionMetadata"] == {"racer": "control"}

    # the genuine, deterministic conflict boundary: once the session has
    # left ACTIVE (ended), UpdateSession is rejected every time -- no race
    # needed to observe this one.
    end_resp = client.end_session(sessionIdentifier=session_id)
    assert end_resp["sessionStatus"] == "ENDED"
    ended_code, ended_message = _error_from_call(
        lambda: client.update_session(
            sessionIdentifier=session_id, sessionMetadata={"racer": "post-end"}
        )
    )
    assert ended_code == "ConflictException", (
        f"expected ConflictException updating an ENDED session, got {ended_code!r}"
    )
    expected_message = f"Session with id {session_id} is in a terminal state and cannot be updated anymore."
    assert ended_message == expected_message, (
        f"expected {expected_message!r} updating an ENDED session, got {ended_message!r}"
    )
    # the rejected post-end write left no trace: metadata is still exactly
    # the control writer's payload.
    after_end = client.get_session(sessionIdentifier=session_id)
    assert after_end["sessionMetadata"] == {"racer": "control"}
    assert after_end["sessionStatus"] == "ENDED"


def _error_code(exc: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code")
    return None


def _error_from_call(fn) -> tuple[str | None, str | None]:
    """Call fn(); return the ClientError (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return _error_code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _cleanup_session(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
    try:
        client.end_session(sessionIdentifier=session_id)
    except ClientError as exc:
        err = exc.response["Error"]
        # The body ends the session itself; AWS answers a second EndSession with this conflict.
        ended = (err["Code"], err.get("Message")) == ("ConflictException", "Cannot end a terminated session")
        if err["Code"] != "ResourceNotFoundException" and not ended:
            raise
    try:
        client.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
