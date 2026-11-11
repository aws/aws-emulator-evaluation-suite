"""browser-session-lifecycle."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags


CHECK = "browser-session-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

# AWS-managed built-in browser tool, usable without any prior CreateBrowser call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html
_BUILTIN_BROWSER = "aws.browser.v1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartBrowserSession creates a READY session that echoes the requested viewPort and timeout,
    exposes the documented stream structure and a current createdAt, and StopBrowserSession
    moves it to TERMINATED."""
    client = ctx.client("bedrock-agentcore")

    requested_width, requested_height = 1280, 900
    requested_timeout = 600
    start = client.start_browser_session(
        browserIdentifier=_BUILTIN_BROWSER,
        sessionTimeoutSeconds=requested_timeout,
        viewPort={"width": requested_width, "height": requested_height},
    )
    session_id = start["sessionId"]
    ctx.on_cleanup(lambda: _best_effort_stop(client, session_id))

    got = client.get_browser_session(browserIdentifier=_BUILTIN_BROWSER, sessionId=session_id)
    assert got["sessionId"] == session_id
    assert got["browserIdentifier"] == _BUILTIN_BROWSER
    assert got["status"] == "READY"

    # Representation depth: the requested configuration is echoed back verbatim.
    assert got["sessionTimeoutSeconds"] == requested_timeout
    assert got["viewPort"]["width"] == requested_width
    assert got["viewPort"]["height"] == requested_height

    # Representation depth: the documented stream sub-structure is populated with real
    # endpoint strings and a status, not just present-but-empty.
    streams = got["streams"]
    assert isinstance(streams["liveViewStream"]["streamEndpoint"], str)
    assert streams["liveViewStream"]["streamEndpoint"]
    assert isinstance(streams["automationStream"]["streamEndpoint"], str)
    assert streams["automationStream"]["streamEndpoint"]
    assert streams["automationStream"]["streamStatus"] == "ENABLED", (
        f"expected automationStream streamStatus ENABLED on a freshly-started READY "
        f"session, got {streams['automationStream']['streamStatus']!r}"
    )

    # Representation depth: createdAt is a real, recent, parseable timestamp.
    created_at = _parse_timestamp(got["createdAt"])
    now = _dt.datetime.now(_dt.timezone.utc)
    assert abs((now - created_at).total_seconds()) < 300

    client.stop_browser_session(browserIdentifier=_BUILTIN_BROWSER, sessionId=session_id)

    final = _poll_until(
        lambda: client.get_browser_session(browserIdentifier=_BUILTIN_BROWSER, sessionId=session_id),
        lambda r: r["status"] == "TERMINATED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["status"] == "TERMINATED"


# ===== helpers =====
def _parse_timestamp(value) -> "_dt.datetime":
    if isinstance(value, _dt.datetime):
        dt = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = _dt.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _best_effort_stop(client, session_id: str) -> None:
    # An already-terminated session answers ConflictException: the teardown goal holds.
    from botocore.exceptions import ClientError

    try:
        client.stop_browser_session(browserIdentifier=_BUILTIN_BROWSER, sessionId=session_id)
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
