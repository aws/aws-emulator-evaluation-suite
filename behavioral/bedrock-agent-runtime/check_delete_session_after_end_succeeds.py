"""delete-session-after-end-succeeds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-session-after-end-succeeds"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After EndSession, DeleteSession succeeds and the session becomes permanently unreachable."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

    # Best-effort cleanup in case an assertion fails before we reach the delete call.
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

    client.end_session(sessionIdentifier=session_id)
    client.delete_session(sessionIdentifier=session_id)
    expected_message = f"Session with ID {session_id} not found"

    try:
        client.get_session(sessionIdentifier=session_id)
        raise AssertionError("expected GetSession to fail after DeleteSession")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # a mutation on the dead id also fails, not just a read
    try:
        client.end_session(sessionIdentifier=session_id)
        raise AssertionError("expected EndSession to fail after DeleteSession")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
