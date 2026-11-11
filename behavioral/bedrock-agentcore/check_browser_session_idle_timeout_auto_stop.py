"""browser-session-idle-timeout-auto-stop."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-session-idle-timeout-auto-stop"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agentcore"]

_SESSION_TIMEOUT_S = 15


# timing:real-time — ttl: 15 s https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_StartBrowserSession.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A browser session started with a short sessionTimeoutSeconds moves from READY to
    TERMINATED once that time-to-live elapses, without any StopBrowserSession call: the
    timeout is a session TTL that fires regardless of activity."""
    agentcore = ctx.client("bedrock-agentcore")

    start = agentcore.start_browser_session(
        browserIdentifier="aws.browser.v1",
        name=ctx.unique_name("sim2real-idle-")[:100],
        sessionTimeoutSeconds=_SESSION_TIMEOUT_S,
    )
    session_id = start["sessionId"]
    ctx.on_cleanup(
        lambda: _safe_stop(agentcore, "aws.browser.v1", session_id)
    )

    initial = agentcore.get_browser_session(
        browserIdentifier="aws.browser.v1", sessionId=session_id
    )
    assert initial["status"] == "READY", (
        f"expected a freshly started browser session to read back READY, "
        f"got status={initial['status']!r}"
    )

    # The deadline leaves margin for the service to reap the session after its TTL.
    budget = _SESSION_TIMEOUT_S + 90
    left = ctx.time_left()
    if left is not None:
        budget = min(budget, left)
    deadline = time.monotonic() + budget
    final_status = initial["status"]
    while time.monotonic() < deadline:
        time.sleep(2)
        resp = agentcore.get_browser_session(
            browserIdentifier="aws.browser.v1", sessionId=session_id
        )
        final_status = resp["status"]
        if final_status == "TERMINATED":
            break

    assert final_status == "TERMINATED", (
        f"browser session did not auto-terminate after its {_SESSION_TIMEOUT_S}s session timeout, "
        f"last observed status={final_status}"
    )


# ===== helpers =====
def _safe_stop(agentcore, browser_identifier: str, session_id: str) -> None:
    # An already-terminated session answers ConflictException: the teardown goal holds.
    try:
        agentcore.stop_browser_session(
            browserIdentifier=browser_identifier, sessionId=session_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
