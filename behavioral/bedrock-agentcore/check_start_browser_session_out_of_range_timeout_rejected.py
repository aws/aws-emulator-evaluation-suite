"""start-browser-session-out-of-range-timeout-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-browser-session-out-of-range-timeout-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]

# AWS-managed built-in browser tool, usable without any prior CreateBrowser call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html
_BUILTIN_BROWSER = "aws.browser.v1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartBrowserSession with sessionTimeoutSeconds above the documented 28800 maximum is
    refused with ValidationException before the browserIdentifier is looked up, while in-range
    calls succeed (positive control) or reach ResourceNotFoundException for a missing browser."""
    agentcore = ctx.client("bedrock-agentcore")
    browser_identifier = "sim2real-missing-browser-does-not-exist"

    # Positive control: a real browserIdentifier and an in-range timeout succeed, so the
    # rejections below cannot be explained by StartBrowserSession being refused outright.
    control = agentcore.start_browser_session(
        browserIdentifier=_BUILTIN_BROWSER, sessionTimeoutSeconds=3600
    )
    control_session_id = control["sessionId"]
    ctx.on_cleanup(lambda: _best_effort_stop(agentcore, control_session_id))
    assert control["browserIdentifier"] == _BUILTIN_BROWSER, (
        f"positive control echoed browserIdentifier {control['browserIdentifier']!r}, "
        f"expected {_BUILTIN_BROWSER!r}"
    )

    # Primary assertion: out-of-range sessionTimeoutSeconds -> ValidationException.
    code, message = _error(
        lambda: agentcore.start_browser_session(
            browserIdentifier=browser_identifier, sessionTimeoutSeconds=28801
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value at 'sessionTimeoutSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 28800"
    ), f"expected the exact sessionTimeoutSeconds range message, got {message!r}"

    # Contrast: same nonexistent browserIdentifier with a valid timeout reaches the
    # existence check instead.
    contrast_code, contrast_message = _error(
        lambda: agentcore.start_browser_session(
            browserIdentifier=browser_identifier, sessionTimeoutSeconds=3600
        )
    )
    assert contrast_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for missing browserIdentifier, got {contrast_code}"
    )
    assert contrast_message == f"Browser not found: {browser_identifier}", (
        f"expected the exact browser-not-found message, got {contrast_message!r}"
    )


# ===== helpers =====

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


def _best_effort_stop(client, session_id: str) -> None:
    # An already-terminated session answers ConflictException: the teardown goal holds.
    from botocore.exceptions import ClientError

    try:
        client.stop_browser_session(browserIdentifier=_BUILTIN_BROWSER, sessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
