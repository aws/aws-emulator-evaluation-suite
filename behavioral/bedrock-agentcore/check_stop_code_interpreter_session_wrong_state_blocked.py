"""stop-code-interpreter-session-wrong-state-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-code-interpreter-session-wrong-state-blocked"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

_BUILTIN_CODE_INTERPRETER = "aws.codeinterpreter.v1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Stopping an already TERMINATED code interpreter session is refused with ConflictException
    rather than succeeding again; the first stop (positive control) succeeds, and the refused
    second stop leaves the session TERMINATED."""
    client = ctx.client("bedrock-agentcore")

    start = client.start_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionTimeoutSeconds=600
    )
    session_id = start["sessionId"]
    ctx.on_cleanup(lambda: _best_effort_stop(client, session_id))

    # Positive control: stopping an active (READY) session succeeds.
    client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
    )
    terminated = _poll_until(
        lambda: client.get_code_interpreter_session(
            codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
        ),
        lambda r: r["status"] == "TERMINATED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert terminated["status"] == "TERMINATED", (
        f"expected TERMINATED after the positive-control stop, got {terminated['status']!r}"
    )

    # Negative: stopping an already-TERMINATED session is a state conflict, not a no-op.
    code, message = _error(
        lambda: client.stop_code_interpreter_session(
            codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == f"Session already terminated: {session_id}", (
        f"expected the exact already-terminated message for {session_id!r}, got {message!r}"
    )

    # Effect absent: the session is still exactly as it was after the first (successful) stop.
    after = client.get_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
    )
    assert after["status"] == "TERMINATED", (
        f"rejected second stop changed status away from TERMINATED, got {after['status']!r}"
    )
    assert after["sessionId"] == session_id, (
        f"expected sessionId {session_id!r} on the independent read, got {after['sessionId']!r}"
    )


# ===== helpers =====
def _best_effort_stop(client, session_id: str) -> None:
    # An already-terminated session answers ConflictException: the teardown goal holds.
    from botocore.exceptions import ClientError

    try:
        client.stop_code_interpreter_session(
            codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target accepting what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
