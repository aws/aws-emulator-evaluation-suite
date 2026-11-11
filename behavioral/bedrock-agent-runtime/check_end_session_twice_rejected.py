"""end-session-twice-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "end-session-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The first EndSession call succeeds (positive control); calling EndSession again on
    an already-ENDED session is rejected with ConflictException and the session status is
    left unchanged at ENDED."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    first = client.end_session(sessionIdentifier=session_id)
    assert first["sessionStatus"] == "ENDED"

    code, message = _error(lambda: client.end_session(sessionIdentifier=session_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Cannot end a terminated session", (
        f"expected message 'Cannot end a terminated session', got {message!r}"
    )

    still_ended = client.get_session(sessionIdentifier=session_id)
    assert still_ended["sessionStatus"] == "ENDED"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


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
