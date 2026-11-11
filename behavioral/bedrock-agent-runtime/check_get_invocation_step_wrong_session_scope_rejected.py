"""get-invocation-step-wrong-session-scope-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-invocation-step-wrong-session-scope-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An invocationStepId is scoped to the session it was written in: fetching it through an
    unrelated second session (same invocationIdentifier value reused) 404s, while it remains
    fetchable through its real, owning session."""
    client = ctx.client("bedrock-agent-runtime")
    session_a = client.create_session(tags={"simparity-check": CHECK})["sessionId"]
    session_b = client.create_session(tags={"simparity-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_a))
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_b))

    invocation_id = client.create_invocation(sessionIdentifier=session_a)["invocationId"]
    step_id = client.put_invocation_step(
        sessionIdentifier=session_a,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "belongs to session A"}]},
    )["invocationStepId"]

    # break exactly one thing: look up A's step scoped under unrelated session B
    code, message = _error(
        lambda: client.get_invocation_step(
            sessionIdentifier=session_b,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for cross-session scope, got {code!r}"
    )
    expected_message = (
        f"Combination of Invocation with ID {invocation_id} and Invcoation Step with ID {step_id} "
        f"not found"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: the step is still fetchable, unharmed, through its real owning session A
    fetched = client.get_invocation_step(
        sessionIdentifier=session_a,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]
    assert fetched["payload"]["contentBlocks"][0]["text"] == "belongs to session A"


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
