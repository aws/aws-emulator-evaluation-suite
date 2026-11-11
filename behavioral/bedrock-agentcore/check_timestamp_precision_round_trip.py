"""timestamp-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "timestamp-precision-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartBrowserSession's server-assigned createdAt is returned with identical precision by GetBrowserSession."""
    data = ctx.client("bedrock-agentcore")
    # Built-in system browser tool: no control-plane Browser resource needs to be provisioned.
    browser_identifier = "aws.browser.v1"

    started = data.start_browser_session(
        browserIdentifier=browser_identifier, sessionTimeoutSeconds=60
    )
    session_id = started["sessionId"]
    created_at = started["createdAt"]
    ctx.on_cleanup(
        lambda: data.stop_browser_session(
            browserIdentifier=browser_identifier, sessionId=session_id
        )
    )

    for attempt in range(3):
        fetched = data.get_browser_session(
            browserIdentifier=browser_identifier, sessionId=session_id
        )
        assert fetched["createdAt"] == created_at, (
            f"createdAt precision changed on read-back #{attempt}: "
            f"start={created_at!r} get={fetched['createdAt']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
