"""create-invocation-on-ended-session-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-on-ended-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvocation succeeds on an ACTIVE session (positive control); once the session
    is ended you can no longer add to it, so CreateInvocation is rejected with
    ConflictException and no second invocation is added to the session."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    first_invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=first_invocation_id)

    client.end_session(sessionIdentifier=session_id)

    second_invocation_id = str(uuid.uuid4())
    code, message = _error(
        lambda: client.create_invocation(
            sessionIdentifier=session_id, invocationId=second_invocation_id
        )
    )
    assert code == "ConflictException", f"expected ConflictException on ended session, got {code}"
    expected_message = (
        f"Session with id {session_id} is in a terminal state and cannot be updated anymore."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    invocation_ids = {
        s["invocationId"]
        for s in client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    }
    assert invocation_ids == {first_invocation_id}, (
        f"expected only the pre-end invocation {first_invocation_id!r} to remain, "
        f"found {invocation_ids!r}"
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
