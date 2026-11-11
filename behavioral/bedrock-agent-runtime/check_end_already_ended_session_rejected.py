"""end-already-ended-session-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "end-already-ended-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second EndSession on an ended session gets ConflictException "Cannot end a terminated session",
    and the invocation and step written before the end stay readable."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"sim2real-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]
    step_id = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "pre-end content"}]},
    )["invocationStepId"]

    # Positive control: ending an ACTIVE session succeeds.
    first_end = client.end_session(sessionIdentifier=session_id)
    assert first_end["sessionStatus"] == "ENDED", (
        f"expected first EndSession to report ENDED, got {first_end.get('sessionStatus')!r}"
    )

    code, message = _error(lambda: client.end_session(sessionIdentifier=session_id))
    assert code == "ConflictException", (
        f"expected second EndSession on an ended session to be rejected with ConflictException, got {code!r}"
    )
    assert message == "Cannot end a terminated session", (
        f"expected message 'Cannot end a terminated session', got {message!r}"
    )

    # the earlier invocation history is untouched by the rejected second EndSession call
    still_there = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]
    got_text = still_there["payload"]["contentBlocks"][0]["text"]
    assert got_text == "pre-end content", (
        f"expected invocation step content to survive the rejected EndSession, got {got_text!r}"
    )

    listed = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    listed_ids = {s["invocationId"] for s in listed}
    assert listed_ids == {invocation_id}, (
        f"expected ListInvocations to still show exactly {{{invocation_id!r}}}, got {listed_ids!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
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
