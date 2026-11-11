"""delete-active-session-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-active-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSession on a still-ACTIVE session is rejected with ConflictException, the
    session is left intact, and the same session can be deleted once legitimately ended
    (positive control)."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))
    assert created["sessionStatus"] == "ACTIVE", (
        f"expected a freshly created session to start ACTIVE, got {created['sessionStatus']!r}"
    )

    code, message = _error(lambda: client.delete_session(sessionIdentifier=session_id))
    assert code == "ConflictException", (
        f"expected DeleteSession on an ACTIVE session to be rejected with ConflictException, got {code!r}"
    )
    assert message == "Cannot delete session in ACTIVE state", (
        f"expected message 'Cannot delete session in ACTIVE state', got {message!r}"
    )

    # effect absent: the session was not deleted
    still_there = client.get_session(sessionIdentifier=session_id)
    assert still_there["sessionStatus"] == "ACTIVE", (
        f"expected the rejected DeleteSession to leave the session ACTIVE, "
        f"got {still_there['sessionStatus']!r}"
    )

    # positive control: end it, then delete succeeds
    client.end_session(sessionIdentifier=session_id)
    client.delete_session(sessionIdentifier=session_id)
    code_after, message_after = _error(lambda: client.get_session(sessionIdentifier=session_id))
    assert code_after == "ResourceNotFoundException", (
        f"expected GetSession to report ResourceNotFoundException after the session was "
        f"ended and deleted, got {code_after!r}"
    )
    expected_message = f"Session with ID {session_id} not found"
    assert message_after == expected_message, (
        f"expected message {expected_message!r}, got {message_after!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
