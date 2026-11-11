"""update-session-after-end-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-session-after-end-rejected"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSession on an ENDED session gets ConflictException with the exact message and leaves the
    metadata unchanged, while an ACTIVE session accepts the update."""
    client = ctx.client("bedrock-agent-runtime")

    ended_session_id = client.create_session()["sessionId"]
    client.update_session(
        sessionIdentifier=ended_session_id, sessionMetadata={"stage": "before-end"}
    )
    client.end_session(sessionIdentifier=ended_session_id)

    def _cleanup_ended():
        try:
            client.delete_session(sessionIdentifier=ended_session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ended)

    before = client.get_session(sessionIdentifier=ended_session_id)["sessionMetadata"]
    assert before == {"stage": "before-end"}, (
        f"expected sessionMetadata {{'stage': 'before-end'}} after the pre-end update, got {before!r}"
    )

    code, message = _error(
        lambda: client.update_session(
            sessionIdentifier=ended_session_id,
            sessionMetadata={"stage": "after-end-should-not-apply"},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        f"Session with id {ended_session_id} is in a terminal state and cannot be updated anymore."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r} updating an ENDED session, got {message!r}"
    )

    # Effect absent: the metadata must be exactly what it was before the
    # rejected update, not the value the rejected call attempted to write.
    after = client.get_session(sessionIdentifier=ended_session_id)["sessionMetadata"]
    assert after == before, (
        f"sessionMetadata changed despite the rejected UpdateSession call: {before} -> {after}"
    )

    # Positive control: a fresh, still-ACTIVE session accepts the identical
    # kind of UpdateSession call without error.
    control_session_id = client.create_session()["sessionId"]

    def _cleanup_control():
        try:
            client.end_session(sessionIdentifier=control_session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            client.delete_session(sessionIdentifier=control_session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_control)

    client.update_session(
        sessionIdentifier=control_session_id, sessionMetadata={"stage": "active-update-ok"}
    )
    control_metadata = client.get_session(sessionIdentifier=control_session_id)["sessionMetadata"]
    assert control_metadata == {"stage": "active-update-ok"}, (
        f"expected sessionMetadata {{'stage': 'active-update-ok'}} on the still-ACTIVE control "
        f"session, got {control_metadata!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
