"""end-session-already-ended-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "end-session-already-ended-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EndSession on an already-ended session is rejected with ConflictException (ENDED is terminal)."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete(client, session_id))

    # Positive control: ending an ACTIVE session succeeds.
    ended = client.end_session(sessionIdentifier=session_id)
    assert ended["sessionStatus"] == "ENDED", (
        f"expected first EndSession to report ENDED, got {ended['sessionStatus']!r}"
    )

    # Negative: ending it again is rejected.
    code, message = _error(lambda: client.end_session(sessionIdentifier=session_id))
    assert code == "ConflictException", (
        f"expected ConflictException from EndSession on an already-ENDED session, got {code!r}"
    )
    assert message == "Cannot end a terminated session", (
        f"expected message 'Cannot end a terminated session', got {message!r}"
    )

    # Effect absent: the session is still exactly ENDED, not mutated by the rejected call.
    got = client.get_session(sessionIdentifier=session_id)
    assert got["sessionStatus"] == "ENDED", (
        f"expected session to remain ENDED after the rejected EndSession, got {got['sessionStatus']!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, Optional[str]]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(client: Any, session_id: str) -> None:
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
