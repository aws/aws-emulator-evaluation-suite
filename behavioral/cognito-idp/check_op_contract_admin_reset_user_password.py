"""op-contract-adminResetUserPassword."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminResetUserPassword"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminResetUserPassword moves a CONFIRMED user to RESET_REQUIRED in AdminGetUser and fails with
    UserNotFoundException and its exact message for a username that does not exist."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    username = _create_user(ctx, pool_id, _unique(ctx, "user"), _PASSWORD)

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "CONFIRMED", before["UserStatus"]

    _admin_reset_user_password_with_backoff(idp, pool_id, username)

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "RESET_REQUIRED", f"expected RESET_REQUIRED, got {after['UserStatus']}"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code = _client_error(
        lambda: _admin_reset_user_password_with_backoff(idp, pool_id, _unique(ctx, "ghost"))
    )
    assert code.get("Code") == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert code.get("Message") == "User does not exist.", code.get("Message")


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_user(ctx, pool_id, username, password=None, permanent=True, attrs=None):
    idp = ctx.client("cognito-idp")
    kwargs = {
        "UserPoolId": pool_id,
        "Username": username,
        "MessageAction": "SUPPRESS",
        "UserAttributes": attrs
        or [
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if password:
        kwargs["TemporaryPassword"] = password
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))
    if password and permanent:
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _safe_delete_user(ctx, pool_id, username) -> None:
    idp = ctx.client("cognito-idp")
    try:
        idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _admin_reset_user_password_with_backoff(idp, pool_id, username, max_attempts=6):
    """Call AdminResetUserPassword, retrying with a bounded backoff if Cognito's
    per-account "attempt limit" throttle (LimitExceededException) fires. Any other
    error (e.g. UserNotFoundException for the error-boundary case) is raised
    immediately."""
    delay = 5.0
    for attempt in range(max_attempts):
        try:
            idp.admin_reset_user_password(UserPoolId=pool_id, Username=username)
            return
        except ClientError as e:
            is_last = attempt == max_attempts - 1
            if e.response["Error"]["Code"] != "LimitExceededException" or is_last:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 60.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
