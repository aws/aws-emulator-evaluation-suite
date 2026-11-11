"""update-session-metadata-persists-while-active."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-session-metadata-persists-while-active"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateSession on an ACTIVE session, two independent GetSession reads each report ACTIVE and
    the exact metadata written."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

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

    metadata = {"purpose": "behavioral-check", "owner": "sim2real"}
    updated = client.update_session(sessionIdentifier=session_id, sessionMetadata=metadata)
    assert updated["sessionStatus"] == "ACTIVE", (
        f"UpdateSession response reported status {updated['sessionStatus']!r}, expected ACTIVE"
    )

    for attempt in range(2):
        fetched = client.get_session(sessionIdentifier=session_id)
        assert fetched["sessionStatus"] == "ACTIVE", (
            f"independent GetSession read #{attempt + 1} reported status "
            f"{fetched['sessionStatus']!r}, expected the session to remain ACTIVE"
        )
        assert fetched["sessionMetadata"] == metadata, (
            f"independent GetSession read #{attempt + 1} returned "
            f"{fetched['sessionMetadata']!r}, expected {metadata!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
