"""console-authorization-configuration-full-lifecycle-workflow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "console-authorization-configuration-full-lifecycle-workflow"
GROUP = "console-authorization"
SERVICES = ["signin"]

NOT_FOUND_MESSAGE = "Console authorization configuration not found"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """Put enables console authorization, Delete answers enabled=false and Get then raises
    ResourceNotFoundException with the exact message, and a second Put re-enables it, read back enabled by
    Get: removal is not a terminal state.
    """
    signin = _east_client(ctx)
    account_id = _account_id(ctx)
    ctx.on_cleanup(lambda: signin.delete_console_authorization_configuration(targetId=account_id))

    signin.put_console_authorization_configuration(targetId=account_id)

    delete_resp = signin.delete_console_authorization_configuration(targetId=account_id)
    assert delete_resp["consoleAuthorizationEnabled"] is False, (
        f"expected Delete's own response to report disabled, got {delete_resp!r}"
    )

    def probe():
        try:
            signin.get_console_authorization_configuration(targetId=account_id)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        return "<get succeeded>", None

    code, message = _poll_until(
        probe, lambda r: r[0] == "ResourceNotFoundException", timeout_s=30.0, interval_s=2.0
    )
    assert code == "ResourceNotFoundException", (
        f"expected the deleted configuration gone via an independent Get, got error code {code!r}"
    )
    assert message == NOT_FOUND_MESSAGE, (
        f"expected message {NOT_FOUND_MESSAGE!r} reading the deleted configuration, got {message!r}"
    )

    resp = signin.put_console_authorization_configuration(targetId=account_id)
    assert resp["consoleAuthorizationEnabled"] is True, (
        f"expected re-Put after delete to re-enable, got {resp!r}"
    )

    get_resp = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_resp["consoleAuthorizationEnabled"] is True, (
        f"expected independent Get to confirm re-enabled, got {get_resp!r}"
    )


def _east_client(ctx):
    """Console-authorization WRITE ops are region-locked to us-east-1 (Put/Delete raise
    ValidationException 'Write operations only supported in us-east' from any other region)."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    if not predicate(last):
        raise AssertionError(f"condition never satisfied within {timeout_s}s (last={last!r})")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
