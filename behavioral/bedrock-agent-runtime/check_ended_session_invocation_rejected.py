"""ended-session-invocation-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ended-session-invocation-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvocation on an ENDED session gets ConflictException with the exact message and records
    nothing, while an ACTIVE session accepts and lists the invocation."""
    client = ctx.client("bedrock-agent-runtime")

    # Positive control: a healthy ACTIVE session accepts a new invocation, and that
    # invocation is independently visible through ListInvocations. This proves the
    # list channel itself surfaces real invocations, so the ended session's empty
    # list below is evidence of absence rather than an artifact of a channel that
    # never reports anything.
    active_session_id = client.create_session(tags={"sim2real-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, active_session_id))
    good = client.create_invocation(sessionIdentifier=active_session_id)
    assert good["invocationId"]
    active_invocation_ids = {
        s["invocationId"]
        for s in client.list_invocations(sessionIdentifier=active_session_id)["invocationSummaries"]
    }
    assert active_invocation_ids == {good["invocationId"]}, (
        f"expected list to reflect the created invocation, found {active_invocation_ids}"
    )

    # Break exactly one thing: end the session before invoking on it.
    ended_session_id = client.create_session(tags={"sim2real-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, ended_session_id))
    end_resp = client.end_session(sessionIdentifier=ended_session_id)
    assert end_resp["sessionStatus"] == "ENDED"

    code, message = _error(lambda: client.create_invocation(sessionIdentifier=ended_session_id))
    assert code == "ConflictException", f"expected ConflictException on ended session, got {code}"
    expected_message = (
        f"Session with id {ended_session_id} is in a terminal state and cannot be updated anymore."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The effect is absent: no invocation was recorded against the ended session.
    invocations = client.list_invocations(sessionIdentifier=ended_session_id).get(
        "invocationSummaries", []
    )
    assert invocations == [], f"expected no invocations on ended session, found {invocations}"


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_session(client, session_id: str) -> None:
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
