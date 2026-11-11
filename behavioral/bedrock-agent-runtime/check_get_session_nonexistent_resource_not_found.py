"""get-session-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSession on a syntactically valid but never-created sessionId returns
    ResourceNotFoundException specifically, while GetSession on a real, still-ACTIVE
    session succeeds (positive control in the same file)."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _end_and_delete(ctx, session_id))

    # Positive control: the session we just created is fetchable and ACTIVE.
    got = client.get_session(sessionIdentifier=session_id)
    assert got["sessionId"] == session_id, (
        f"positive control returned sessionId {got['sessionId']!r}, expected {session_id!r}"
    )
    assert got["sessionStatus"] == "ACTIVE", (
        f'positive control session status was {got["sessionStatus"]!r}, expected "ACTIVE"'
    )

    # A well-formed UUID (matches the sessionIdentifier pattern) that was never created.
    bogus_session_id = str(uuid.uuid4())
    code, message = _error(lambda: client.get_session(sessionIdentifier=bogus_session_id))
    assert code == "ResourceNotFoundException", (
        f"GetSession on a never-created sessionId returned {code!r}, expected "
        f'"ResourceNotFoundException"'
    )
    expected_message = f"Session with ID {bogus_session_id} not found"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _end_and_delete(ctx, session_id: str) -> None:
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"GetSession on a never-created sessionId SUCCEEDED and returned {result!r}, expected "
        f'it to raise "ResourceNotFoundException"'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
