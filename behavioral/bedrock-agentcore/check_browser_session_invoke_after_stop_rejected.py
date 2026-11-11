"""browser-session-invoke-after-stop-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-session-invoke-after-stop-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeBrowser against a stopped (TERMINATED) session is refused with ValidationException
    and performs nothing, while the same action against a fresh READY session succeeds
    (positive control)."""
    agentcore = ctx.client("bedrock-agentcore")
    action = {"screenshot": {}}

    # Positive control: a fresh session can be invoked successfully.
    control_session = agentcore.start_browser_session(
        browserIdentifier="aws.browser.v1",
        name=ctx.unique_name("sim2real-ctrl-")[:100],
        sessionTimeoutSeconds=300,
    )
    control_session_id = control_session["sessionId"]
    ctx.on_cleanup(
        lambda: _safe_stop(agentcore, "aws.browser.v1", control_session_id)
    )
    control_result = agentcore.invoke_browser(
        browserIdentifier="aws.browser.v1", sessionId=control_session_id, action=action
    )
    assert "result" in control_result, (
        f"positive control: expected a 'result' key from invoke_browser against a READY "
        f"session, got keys={sorted(control_result.keys())}"
    )

    # Negative: stop a second session, then invoke against it.
    stopped_session = agentcore.start_browser_session(
        browserIdentifier="aws.browser.v1",
        name=ctx.unique_name("sim2real-stopped-")[:100],
        sessionTimeoutSeconds=300,
    )
    stopped_session_id = stopped_session["sessionId"]
    agentcore.stop_browser_session(
        browserIdentifier="aws.browser.v1", sessionId=stopped_session_id
    )

    code, message = _error(
        lambda: agentcore.invoke_browser(
            browserIdentifier="aws.browser.v1",
            sessionId=stopped_session_id,
            action=action,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"Browser session {stopped_session_id} is not active. "
        "Start a new session or provide a valid session ID"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Confirm the session is indeed terminated (the effect is genuinely absent, not a
    # transient rejection).
    final = agentcore.get_browser_session(
        browserIdentifier="aws.browser.v1", sessionId=stopped_session_id
    )
    assert final["status"] == "TERMINATED", (
        f"expected the stopped session to read back TERMINATED, got {final['status']!r}"
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target accepting a call AWS refuses is the strongest signal available and must not read as
    a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected invoke_browser against a TERMINATED session to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
