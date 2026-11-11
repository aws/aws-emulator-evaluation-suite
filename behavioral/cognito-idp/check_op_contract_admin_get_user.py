"""op-contract-adminGetUser."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminGetUser"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminGetUser returns the user's attributes/status accurately, and rejects a
    username that doesn't exist in the pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    username = _unique(ctx, "user")
    email = f"{username}@example.com"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))

    resp = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert resp["Username"] == username, f"expected Username {username}, got {resp['Username']}"
    assert resp["UserStatus"] == "FORCE_CHANGE_PASSWORD", resp["UserStatus"]
    assert resp["Enabled"] is True, f"expected new user to be Enabled, got {resp['Enabled']}"
    attr_map = {a["Name"]: a["Value"] for a in resp["UserAttributes"]}
    assert attr_map.get("email") == email, f"expected email {email}, got {attr_map.get('email')}"

    # Error boundary: nonexistent username -> UserNotFoundException.
    ghost = _unique(ctx, "ghost")
    code = _client_error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=ghost))
    assert code.get("Code") == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert code.get("Message") == "User does not exist.", code.get("Message")


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault(
        "UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool(idp, pool_id))
    return pool_id


def _delete_user_pool(idp, pool_id) -> None:
    # New pools default to DeletionProtection=ACTIVE, which makes DeleteUserPool fail with
    # InvalidParameterException until it is turned off first.
    try:
        idp.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    idp.delete_user_pool(UserPoolId=pool_id)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
