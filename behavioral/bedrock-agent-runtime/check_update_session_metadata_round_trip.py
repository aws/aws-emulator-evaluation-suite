"""update-session-metadata-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-session-metadata-round-trip"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSession persists sessionMetadata, and it is faithfully returned by a subsequent GetSession."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    metadata = {"customer": "sim2real", "priority": "high"}
    updated = client.update_session(sessionIdentifier=session_id, sessionMetadata=metadata)
    assert updated["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE after UpdateSession, got {updated['sessionStatus']!r}"
    )

    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["sessionMetadata"] == metadata, (
        f"expected sessionMetadata {metadata!r} on GetSession, got {fetched['sessionMetadata']!r}"
    )


def _safe_end_and_delete(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
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
