"""session-create-starts-active."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-create-starts-active"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession returns an ACTIVE session that GetSession subsequently confirms."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session(tags={"sim2real": CHECK})
    session_id = created["sessionId"]

    def _cleanup():
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

    assert created["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE on create, got {created['sessionStatus']!r}"
    )
    assert created["sessionArn"].endswith(session_id), (
        f"expected sessionArn to end with sessionId {session_id!r}, "
        f"got {created['sessionArn']!r}"
    )

    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["sessionStatus"] == "ACTIVE", (
        f"expected independent GetSession read to show ACTIVE, "
        f"got {fetched['sessionStatus']!r}"
    )
    assert fetched["sessionId"] == session_id, (
        f"expected GetSession sessionId {session_id!r}, got {fetched['sessionId']!r}"
    )
    assert fetched["sessionArn"] == created["sessionArn"], (
        f"expected GetSession sessionArn to match create response "
        f"{created['sessionArn']!r}, got {fetched['sessionArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
