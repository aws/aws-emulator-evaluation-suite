"""console-authorization-configuration-disabled-after-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "console-authorization-configuration-disabled-after-delete"
GROUP = "console-authorization"
SERVICES = ["signin"]

NOT_FOUND_MESSAGE = "Console authorization configuration not found"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """DeleteConsoleAuthorizationConfiguration answers consoleAuthorizationEnabled=false and removes the record:
    Get then raises ResourceNotFoundException and a second delete fails the same way, both with the exact
    message.
    """
    signin = _east_client(ctx)
    account_id = _account_id(ctx)

    signin.put_console_authorization_configuration(targetId=account_id)
    ctx.on_cleanup(lambda: _delete_tolerating_not_found(signin, account_id))
    get_after_put = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_after_put["consoleAuthorizationEnabled"] is True, (
        f"expected enabled after put, got {get_after_put!r}"
    )

    delete_resp = signin.delete_console_authorization_configuration(targetId=account_id)
    assert delete_resp["consoleAuthorizationEnabled"] is False, (
        f"expected disabled in delete's own response, got {delete_resp!r}"
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
        f"expected ResourceNotFoundException reading a deleted configuration, got {code!r}"
    )
    assert message == NOT_FOUND_MESSAGE, (
        f"expected message {NOT_FOUND_MESSAGE!r} reading a deleted configuration, got {message!r}"
    )

    # the delete removed the record entirely, not just flipped a flag: a second delete
    # against the now-gone target is itself a not-found, not a silent no-op success
    second_delete_code, second_delete_message = _error(
        lambda: signin.delete_console_authorization_configuration(targetId=account_id)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-removed configuration, got {second_delete_code!r}"
    )
    assert second_delete_message == NOT_FOUND_MESSAGE, (
        f"expected message {NOT_FOUND_MESSAGE!r} deleting an already-removed configuration, "
        f"got {second_delete_message!r}"
    )


def _east_client(ctx):
    """Console-authorization WRITE ops are region-locked to us-east-1 (Put/Delete raise
    ValidationException 'Write operations only supported in us-east' from any other region)."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_tolerating_not_found(signin, target_id: str) -> None:
    try:
        signin.delete_console_authorization_configuration(targetId=target_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
