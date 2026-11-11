"""get-console-authorization-configuration-not-found-when-unset."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-console-authorization-configuration-not-found-when-unset"
GROUP = "console-authorization"
SERVICES = ["signin"]

NOT_FOUND_MESSAGE = "Console authorization configuration not found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """GetConsoleAuthorizationConfiguration raises ResourceNotFoundException for a target with no
    configuration record rather than a default disabled record, after a positive control (Put
    then Get) proves Get reports an enabled configuration."""
    signin = _east_client(ctx)
    account_id = _account_id(ctx)

    _safe_delete(signin, account_id)

    put_resp = signin.put_console_authorization_configuration(targetId=account_id)
    ctx.on_cleanup(lambda: _safe_delete(signin, account_id))
    assert put_resp["consoleAuthorizationEnabled"] is True, (
        f"positive control: expected the initial Put to enable, got {put_resp!r}"
    )
    get_after_put = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_after_put["consoleAuthorizationEnabled"] is True, (
        f"positive control: expected Get to report the enabled config, got {get_after_put!r}"
    )

    signin.delete_console_authorization_configuration(targetId=account_id)

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
        f"expected ResourceNotFoundException for an unconfigured target, got {code!r}"
    )
    assert message == NOT_FOUND_MESSAGE, (
        f"expected message {NOT_FOUND_MESSAGE!r} reading the deleted configuration, got {message!r}"
    )


# ===== helpers =====
def _east_client(ctx):
    """Console-authorization WRITE ops are region-locked to us-east-1 (Put/Delete raise
    ValidationException 'Write operations only supported in us-east' from any other region)."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _safe_delete(signin, account_id: str) -> None:
    try:
        signin.delete_console_authorization_configuration(targetId=account_id)
    except ClientError as exc:
        # Deleting an unset configuration raises ResourceNotFoundException: already clean.
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
