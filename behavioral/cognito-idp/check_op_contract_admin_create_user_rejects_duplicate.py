"""op-contract-adminCreateUser."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminCreateUser"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser creates an enabled FORCE_CHANGE_PASSWORD user with the requested email, a duplicate
    Username fails with UsernameExistsException and its exact message and leaves that user as it was,
    and after deletion the same call succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    username = _unique(ctx, "user")
    email = f"{username}@example.com"

    def _create():
        return idp.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            TemporaryPassword=_PASSWORD,
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": email}],
        )["User"]

    def _assert_created(user) -> None:
        assert user["Username"] == username
        assert user["UserStatus"] == "FORCE_CHANGE_PASSWORD", user["UserStatus"]
        assert user["Enabled"] is True
        attr_map = {a["Name"]: a["Value"] for a in user["Attributes"]}
        assert attr_map.get("email") == email

    def _assert_persisted() -> None:
        got = idp.admin_get_user(UserPoolId=pool_id, Username=username)
        assert got["UserStatus"] == "FORCE_CHANGE_PASSWORD", got["UserStatus"]
        assert got["Enabled"] is True
        attr_map = {a["Name"]: a["Value"] for a in got["UserAttributes"]}
        assert attr_map.get("email") == email

    _assert_created(_create())
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))

    # Negative: creating the same Username again must be rejected as a duplicate,
    # not silently overwritten or accepted.
    code = _client_error(
        lambda: idp.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            TemporaryPassword=_PASSWORD,
            MessageAction="SUPPRESS",
        )
    )
    assert code.get("Code") == "UsernameExistsException", f"expected UsernameExistsException, got {code}"
    assert code.get("Message") == "User account already exists", code.get("Message")

    # Effect-absent: the rejected duplicate must not have touched the original user
    # (still FORCE_CHANGE_PASSWORD, still the original email) -- an independent read
    # through admin_get_user, not the mutating admin_create_user's own response.
    _assert_persisted()

    # Restore: freeing the username (deleting the user) must make the identical
    # create call succeed again -- the rejection is a live-username conflict, not a
    # permanent ban on the string. Terminal assertion is an independent admin_get_user
    # read of the recreated user, never the mutating call's own response.
    idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    _assert_created(_create())
    _assert_persisted()


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault(
        "UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


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
