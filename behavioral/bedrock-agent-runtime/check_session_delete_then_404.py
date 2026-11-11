"""session-delete-then-404."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-delete-then-404"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteSession completes, GetSession on that id returns ResourceNotFoundException,
    and a mutating call (EndSession) on the same dead id is rejected the same way."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    client.end_session(sessionIdentifier=session_id)
    client.delete_session(sessionIdentifier=session_id)

    get_message = _poll_until_error_code(
        lambda: client.get_session(sessionIdentifier=session_id),
        expected="ResourceNotFoundException",
        timeout_s=30.0,
    )
    expected_message = f"Session with ID {session_id} not found"
    assert get_message == expected_message, (
        f"expected GetSession message {expected_message!r}, got {get_message!r}"
    )

    mutate_code, mutate_message = _error(lambda: client.end_session(sessionIdentifier=session_id))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected EndSession on a deleted session to raise ResourceNotFoundException, "
        f"got {mutate_code!r}"
    )
    assert mutate_message == expected_message, (
        f"expected EndSession message {expected_message!r}, got {mutate_message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, Optional[str]]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_error_code(
    fn: Callable[[], Any], *, expected: str, timeout_s: float = 30.0, interval_s: float = 1.0
) -> Optional[str]:
    """Poll `fn` until it raises a ClientError with code `expected` and return that error's
    message; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last_code: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            fn()
            last_code = None
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == expected:
                return e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {expected} within {timeout_s}s, last observed {last_code!r}"
    )


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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
