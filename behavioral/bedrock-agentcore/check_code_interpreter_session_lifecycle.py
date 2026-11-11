"""code-interpreter-session-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "code-interpreter-session-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

# AWS-managed built-in code interpreter, usable without any prior CreateCodeInterpreter call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-start-session.html
_BUILTIN_CODE_INTERPRETER = "aws.codeinterpreter.v1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCodeInterpreterSession creates a READY session and StopCodeInterpreterSession
    terminates it, reflected in subsequent GetCodeInterpreterSession calls."""
    client = ctx.client("bedrock-agentcore")

    start = client.start_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionTimeoutSeconds=600
    )
    session_id = start["sessionId"]
    ctx.on_cleanup(lambda: _best_effort_stop(client, session_id))

    got = client.get_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
    )
    assert got["sessionId"] == session_id, (
        f"expected GetCodeInterpreterSession to echo back sessionId {session_id!r}, got {got['sessionId']!r}"
    )
    assert got["status"] == "READY", (
        f"expected a freshly started session to read back READY, got {got['status']!r}"
    )

    client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
    )

    final = _poll_until(
        lambda: client.get_code_interpreter_session(
            codeInterpreterIdentifier=_BUILTIN_CODE_INTERPRETER, sessionId=session_id
        ),
        lambda r: r["status"] == "TERMINATED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["status"] == "TERMINATED", (
        f"expected an independent read after StopCodeInterpreterSession to settle at "
        f"TERMINATED, got {final['status']!r}"
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
