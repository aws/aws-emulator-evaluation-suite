"""op-contract-adminDisableUser."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminDisableUser"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminDisableUser flips Enabled to false (observable via AdminGetUser), and
    rejects a username that doesn't exist."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    username = _create_user(ctx, pool_id, _unique(ctx, "user"), _PASSWORD)

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["Enabled"] is True, f"expected freshly created user Enabled=True, got {before['Enabled']!r}"

    idp.admin_disable_user(UserPoolId=pool_id, Username=username)

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["Enabled"] is False, "expected Enabled=False after AdminDisableUser"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code, message = _error(
        lambda: idp.admin_disable_user(UserPoolId=pool_id, Username=_unique(ctx, "ghost"))
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert message == "User does not exist.", message


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
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


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
