"""malformed-session-id-input-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-session-id-input-rejected"
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
    """CreateInvocation with a malformed sessionIdentifier gets ValidationException with the exact
    message, while a real session accepts and lists exactly one invocation."""
    client = ctx.client("bedrock-agent-runtime")
    session = client.create_session()
    session_id = session["sessionId"]

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

    # Neither a bare-uuid nor an ARN form; fails the sessionIdentifier pattern.
    malformed_session_id = "not-a-valid-session-id"

    def bad_call():
        client.create_invocation(sessionIdentifier=malformed_session_id)

    code, message = _error(bad_call)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{malformed_session_id}' at 'sessionIdentifier' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: "
        f"{_SESSION_IDENTIFIER_PATTERN}"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # effect absent: the real (unrelated) session has no invocations recorded --
    # the malformed request never reached the backend to create anything, anywhere.
    before = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    assert before == []

    # positive control: an identical call with a well-formed sessionIdentifier
    # succeeds and is observable via ListInvocations.
    created = client.create_invocation(sessionIdentifier=session_id)
    assert created["invocationId"]

    after = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    assert len(after) == 1
    assert after[0]["invocationId"] == created["invocationId"]


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
