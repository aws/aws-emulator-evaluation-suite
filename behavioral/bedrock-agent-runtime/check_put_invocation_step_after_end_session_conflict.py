"""put-invocation-step-after-end-session-conflict."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-invocation-step-after-end-session-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutInvocationStep succeeds on an ACTIVE session, while the same write after EndSession gets
    ConflictException with the exact message and the session keeps only the first step."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session(tags={"purpose": "sim2real-audit"})["sessionId"]
    ctx.on_cleanup(lambda: _end_and_delete(ctx, session_id))
    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    # Positive control: writing a step to the still-ACTIVE session succeeds.
    first_step = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "step-while-active"}]},
    )
    assert "invocationStepId" in first_step, f"expected invocationStepId, got {first_step!r}"

    steps_before = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )["invocationStepSummaries"]
    assert len(steps_before) == 1, f"expected 1 step while active, got {len(steps_before)}"

    ended = client.end_session(sessionIdentifier=session_id)
    assert ended["sessionStatus"] == "ENDED", f"expected ENDED, got {ended['sessionStatus']!r}"

    code, message = _error(
        lambda: client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepTime=datetime.now(timezone.utc),
            payload={"contentBlocks": [{"text": "step-after-end"}]},
        )
    )
    assert code == "ConflictException", f"expected ConflictException on ended session, got {code}"
    expected_message = (
        f"Session with id {session_id} is in a terminal state and cannot be updated anymore."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected write left no second step behind.
    steps_after = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )["invocationStepSummaries"]
    assert len(steps_after) == 1, f"expected still 1 step after rejected write, got {len(steps_after)}"
    assert steps_after[0]["invocationStepId"] == first_step["invocationStepId"], (
        f"expected surviving step to be the original {first_step['invocationStepId']!r}, "
        f"got {steps_after[0]['invocationStepId']!r}"
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
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the write to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
