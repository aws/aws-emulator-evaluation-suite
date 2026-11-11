"""create-session-concurrent-calls-return-distinct-sessions."""
from __future__ import annotations

import threading
from typing import Any

from behavioral_harness import tags

CHECK = "create-session-concurrent-calls-return-distinct-sessions"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five racing CreateSession calls (which take no client identifier or token) each get a distinct
    ACTIVE session holding exactly its own sessionMetadata: no spurious conflict, dedupe or merge."""
    client = ctx.client("bedrock-agent-runtime")
    racer_tags = [f"racer-{i}" for i in range(5)]
    barrier = threading.Barrier(len(racer_tags))
    results: dict[str, tuple[str, Any]] = {}

    def _create(tag: str) -> None:
        barrier.wait()
        try:
            resp = client.create_session(
                sessionMetadata={"racer": tag}, tags={"env": "test"}
            )
            results[tag] = ("ok", resp)
        except Exception as exc:  # noqa: BLE001
            results[tag] = ("error", _error_code(exc))

    threads = [threading.Thread(target=_create, args=(tag,)) for tag in racer_tags]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    session_ids: dict[str, str] = {}
    for tag in racer_tags:
        kind, payload = results[tag]
        assert kind == "ok", f"racer {tag} unexpectedly failed: {payload}"
        session_ids[tag] = payload["sessionId"]
        assert payload["sessionStatus"] == "ACTIVE", (
            f"racer {tag}: expected sessionStatus ACTIVE, got {payload['sessionStatus']!r}"
        )
        ctx.on_cleanup(lambda sid=payload["sessionId"]: _cleanup_session(ctx, sid))

    # no accidental dedup / collision under concurrency: every racer got its
    # own distinct session.
    assert len(set(session_ids.values())) == len(racer_tags), (
        f"expected {len(racer_tags)} distinct sessionIds, got {session_ids}"
    )

    # each session independently persisted exactly the metadata its own
    # creator sent -- never another racer's, never a merge.
    for tag, sid in session_ids.items():
        session = client.get_session(sessionIdentifier=sid)
        assert session["sessionMetadata"] == {"racer": tag}, (
            f"session {sid} (racer {tag}): expected sessionMetadata "
            f"{{'racer': {tag!r}}}, got {session['sessionMetadata']!r}"
        )


# ===== helpers =====
def _error_code(exc: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code")
    return None


def _cleanup_session(ctx, session_id: str) -> None:
    """End the session if still ACTIVE (DeleteSession refuses an ACTIVE one), then delete it."""
    from botocore.exceptions import ClientError

    client = ctx.client("bedrock-agent-runtime")
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        client.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
