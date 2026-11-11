"""get-session-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-not-found"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]

# The sessionIdentifier pattern, exactly as the service quotes it back in the refusal.
_SESSION_IDENTIFIER_PATTERN = (
    "((arn:aws(-[^:]+)?:bedrock:[a-z0-9-]+:[0-9]{12}:session/"
    "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"
    "|([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}))"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSession with a sessionIdentifier that is neither a valid UUID nor a valid session
    ARN is rejected with ValidationException (the format constraint is enforced server-side);
    GetSession against a real session (positive control, same file) succeeds normally."""
    client = ctx.client("bedrock-agent-runtime")

    # break exactly one thing: a sessionIdentifier that matches neither the UUID nor ARN pattern
    malformed_id = "not-a-uuid-and-not-an-arn!!!"
    code, message = _error(lambda: client.get_session(sessionIdentifier=malformed_id))
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed sessionIdentifier, got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'sessionIdentifier' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: "
        f"{_SESSION_IDENTIFIER_PATTERN}"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: a real session is fetched successfully
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))
    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["sessionId"] == session_id, (
        f"expected GetSession to return sessionId {session_id!r}, got {fetched.get('sessionId')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_end_and_delete(ctx, session_id: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
