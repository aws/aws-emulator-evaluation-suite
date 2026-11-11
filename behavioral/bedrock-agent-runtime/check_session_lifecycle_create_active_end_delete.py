"""session-lifecycle-create-active-end-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "session-lifecycle-create-active-end-delete"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A session transitions ACTIVE -> ENDED -> deleted, and GetSession reflects each state."""
    client = ctx.client("bedrock-agent-runtime")

    session_meta = {"purpose": "sim2real-behavioral-check"}
    created = client.create_session(sessionMetadata=session_meta)
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    # Per the CreateSession contract, the initial sessionStatus is always ACTIVE.
    assert created["sessionStatus"] == "ACTIVE", (
        f"expected initial sessionStatus ACTIVE, got {created['sessionStatus']!r}"
    )
    # Representation: the ARN is a real Bedrock session ARN naming this exact session.
    assert session_arn.startswith("arn:aws:bedrock:"), (
        f"expected sessionArn to start with 'arn:aws:bedrock:', got {session_arn!r}"
    )
    assert session_arn.endswith(f"session/{session_id}"), (
        f"expected sessionArn to end with 'session/{session_id}', got {session_arn!r}"
    )
    created_at = created["createdAt"]

    def _cleanup() -> None:
        # DeleteSession rejects an ACTIVE session, so make sure it is ended first (best effort,
        # in case an assertion above failed before the session reached ENDED).
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

    ctx.on_cleanup(_cleanup)

    got_active = client.get_session(sessionIdentifier=session_id)
    assert got_active["sessionId"] == session_id, (
        f"expected GetSession sessionId {session_id!r}, got {got_active['sessionId']!r}"
    )
    assert got_active["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE before EndSession, got {got_active['sessionStatus']!r}"
    )
    assert got_active["sessionArn"] == session_arn, (
        f"expected sessionArn {session_arn!r}, got {got_active['sessionArn']!r}"
    )
    # Representation: the metadata supplied at creation is echoed back verbatim.
    assert got_active["sessionMetadata"] == session_meta, (
        f"expected sessionMetadata {session_meta!r}, got {got_active['sessionMetadata']!r}"
    )
    assert got_active["createdAt"] == created_at, (
        f"expected createdAt {created_at!r} unchanged, got {got_active['createdAt']!r}"
    )
    # Representation: lastUpdatedAt is a real timestamp no earlier than createdAt.
    assert got_active["lastUpdatedAt"] >= created_at, (
        f"expected lastUpdatedAt {got_active['lastUpdatedAt']!r} >= createdAt {created_at!r}"
    )

    ended = client.end_session(sessionIdentifier=session_id)
    assert ended["sessionId"] == session_id, (
        f"expected EndSession sessionId {session_id!r}, got {ended['sessionId']!r}"
    )
    assert ended["sessionStatus"] == "ENDED", (
        f"expected sessionStatus ENDED after EndSession, got {ended['sessionStatus']!r}"
    )

    got_ended = client.get_session(sessionIdentifier=session_id)
    assert got_ended["sessionStatus"] == "ENDED", (
        f"expected sessionStatus ENDED on independent read, got {got_ended['sessionStatus']!r}"
    )
    # Representation: ending the session advances lastUpdatedAt but leaves createdAt/ARN fixed.
    assert got_ended["createdAt"] == created_at, (
        f"expected createdAt {created_at!r} unchanged after EndSession, got {got_ended['createdAt']!r}"
    )
    assert got_ended["sessionArn"] == session_arn, (
        f"expected sessionArn {session_arn!r} unchanged after EndSession, got {got_ended['sessionArn']!r}"
    )
    assert got_ended["lastUpdatedAt"] >= got_active["lastUpdatedAt"], (
        f"expected lastUpdatedAt {got_ended['lastUpdatedAt']!r} >= prior "
        f"{got_active['lastUpdatedAt']!r} after EndSession"
    )

    # An ENDED session is terminal for writes but can still be deleted, which removes it entirely.
    client.delete_session(sessionIdentifier=session_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
