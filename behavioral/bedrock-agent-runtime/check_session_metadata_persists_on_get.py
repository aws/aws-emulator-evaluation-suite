"""session-metadata-persists-on-get."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-metadata-persists-on-get"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """sessionMetadata supplied at CreateSession round-trips exactly through GetSession,
    and UpdateSession fully replaces it (not merges) while the session stays ACTIVE."""
    client = ctx.client("bedrock-agent-runtime")

    initial_metadata = {"topic": "billing-question", "user": "alice"}
    created = client.create_session(sessionMetadata=initial_metadata)
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    got = client.get_session(sessionIdentifier=session_id)
    assert got["sessionMetadata"] == initial_metadata, (
        f"expected sessionMetadata {initial_metadata!r} to round-trip through GetSession, "
        f"got {got.get('sessionMetadata')!r}"
    )

    updated_metadata = {"topic": "refund-request"}
    updated = client.update_session(
        sessionIdentifier=session_id, sessionMetadata=updated_metadata
    )
    assert updated["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE after UpdateSession, got {updated.get('sessionStatus')!r}"
    )

    got_after_update = client.get_session(sessionIdentifier=session_id)
    assert got_after_update["sessionMetadata"] == updated_metadata, (
        f"expected sessionMetadata to be fully replaced with {updated_metadata!r}, "
        f"got {got_after_update.get('sessionMetadata')!r}"
    )
    assert "user" not in got_after_update["sessionMetadata"], (
        "UpdateSession merged instead of replacing sessionMetadata: stale key 'user' "
        f"survived an update that omitted it (full map: {got_after_update['sessionMetadata']!r})"
    )


def _safe_delete_session(client, session_id: str) -> None:
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
