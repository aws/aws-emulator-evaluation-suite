"""get-session-nonexistent-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-session-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSession on a real session succeeds (positive control); GetSession on a
    well-formed but never-created sessionId is rejected with ResourceNotFoundException."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    control = client.get_session(sessionIdentifier=session_id)
    assert control["sessionId"] == session_id, (
        f"expected sessionId {session_id!r}, got {control['sessionId']!r}"
    )
    assert control["sessionStatus"] == "ACTIVE", (
        f"expected positive control session ACTIVE, got {control['sessionStatus']!r}"
    )

    bogus_id = str(uuid.uuid4())
    code, message = _error(lambda: client.get_session(sessionIdentifier=bogus_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created sessionId, got {code!r}"
    )
    expected_message = f"Session with ID {bogus_id} not found"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetSession on a never-created sessionId to raise, but it succeeded with {result!r}"
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
