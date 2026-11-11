"""delete-session-twice-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-session-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSession on a session that was already deleted is rejected with ResourceNotFoundException,
    it does not silently succeed a second time."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))
    client.end_session(sessionIdentifier=session_id)

    # positive control: the first delete succeeds
    client.delete_session(sessionIdentifier=session_id)

    # break exactly one thing: delete the same, now already-deleted session again
    expected_message = f"Session with ID {session_id} not found"
    code, message = _error(lambda: client.delete_session(sessionIdentifier=session_id))
    assert code == "ResourceNotFoundException", (
        f"expected second DeleteSession to be rejected with ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: still gone, GetSession agrees it does not exist
    code_get, message_get = _error(lambda: client.get_session(sessionIdentifier=session_id))
    assert code_get == "ResourceNotFoundException", (
        f"expected GetSession on the deleted session to be ResourceNotFoundException, got {code_get!r}"
    )
    assert message_get == expected_message, (
        f"expected message {expected_message!r}, got {message_get!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
