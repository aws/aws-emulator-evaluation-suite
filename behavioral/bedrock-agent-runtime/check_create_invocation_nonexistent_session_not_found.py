"""create-invocation-nonexistent-session-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-nonexistent-session-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvocation on a never-created session gets ResourceNotFoundException "Session with ID <id>
    not found"; on a real session it succeeds and the invocation is listed."""
    client = ctx.client("bedrock-agent-runtime")

    bogus_session_id = str(uuid.uuid4())
    code, message = _error(lambda: client.create_invocation(sessionIdentifier=bogus_session_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created sessionIdentifier, got {code!r}"
    )
    expected_message = f"Session with ID {bogus_session_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control
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

    created = client.create_invocation(sessionIdentifier=session_id)
    invocation_id = created.get("invocationId")
    assert invocation_id, f"expected an invocationId in the create_invocation response, got {created!r}"

    summaries = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    listed_ids = {s["invocationId"] for s in summaries}
    assert invocation_id in listed_ids, (
        f"expected {invocation_id!r} to appear in list_invocations for session {session_id!r}, "
        f"saw {listed_ids!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected ResourceNotFoundException for a never-created sessionIdentifier, "
        f"but the call succeeded with {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
