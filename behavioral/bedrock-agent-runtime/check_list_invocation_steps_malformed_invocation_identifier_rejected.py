"""list-invocation-steps-malformed-invocation-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-invocation-steps-malformed-invocation-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps rejects an invocationIdentifier that isn't a well-formed UUID with
    ValidationException (the regex constraint is enforced server-side, not by the SDK), while
    omitting the filter (positive control) succeeds normally against the same real session."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "sim2real"})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    # break exactly one thing: an invocationIdentifier that is not a UUID at all
    malformed_id = "not-a-valid-uuid"
    code, message = _error(
        lambda: client.list_invocation_steps(
            sessionIdentifier=session_id, invocationIdentifier=malformed_id
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed invocationIdentifier, got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'invocationIdentifier' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: "
        f"[a-f0-9]{{8}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{12}}"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: the same session, listed without the malformed filter, succeeds
    resp = client.list_invocation_steps(sessionIdentifier=session_id)
    assert resp["invocationStepSummaries"] == [], (
        f"expected no invocation steps on a fresh session, got {resp['invocationStepSummaries']!r}"
    )


def _error(fn):
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
