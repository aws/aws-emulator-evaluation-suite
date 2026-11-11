"""op-contract-adminCreateUser-username-exists-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminCreateUser-username-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser succeeds once (FORCE_CHANGE_PASSWORD, Enabled) then rejects a duplicate
    Username while that username is taken, and accepts it again once the original user is gone."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    username = ctx.unique_name("sim2real-behav-user-")

    resp = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass123",
        MessageAction="SUPPRESS",
    )
    user = resp["User"]
    assert user["Username"] == username, f"expected Username {username!r}, got {user['Username']!r}"
    assert user["UserStatus"] == "FORCE_CHANGE_PASSWORD", user["UserStatus"]
    assert user["Enabled"] is True, f"expected Enabled True, got {user['Enabled']!r}"

    users = idp.list_users(UserPoolId=pool_id)["Users"]
    assert len(users) == 1, f"expected 1 user, got {len(users)}"

    code, message = _error(
        lambda: idp.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            TemporaryPassword="TempPass123",
            MessageAction="SUPPRESS",
        )
    )
    assert (code, message) == ("UsernameExistsException", "User account already exists"), f"expected UsernameExistsException, got {(code, message)!r}"

    users_after = idp.list_users(UserPoolId=pool_id)["Users"]
    assert len(users_after) == 1, f"expected still 1 user after rejected duplicate, got {len(users_after)}"
    assert users_after[0]["UserStatus"] == "FORCE_CHANGE_PASSWORD", users_after[0]["UserStatus"]

    idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    users_after_delete = idp.list_users(UserPoolId=pool_id)["Users"]
    assert len(users_after_delete) == 0, f"expected 0 users after delete, got {len(users_after_delete)}"

    resp2 = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass123",
        MessageAction="SUPPRESS",
    )
    user2 = resp2["User"]
    assert user2["Username"] == username, f"expected Username {username!r} reusable, got {user2['Username']!r}"
    assert user2["UserStatus"] == "FORCE_CHANGE_PASSWORD", user2["UserStatus"]
    users_final = idp.list_users(UserPoolId=pool_id)["Users"]
    assert len(users_final) == 1, f"expected 1 user after re-create, got {len(users_final)}"


def _password_policy():
    return {
        "PasswordPolicy": {
            "MinimumLength": 8,
            "RequireUppercase": False,
            "RequireLowercase": False,
            "RequireNumbers": False,
            "RequireSymbols": False,
            "TemporaryPasswordValidityDays": 7,
        }
    }


def _create_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "Policies": _password_policy(),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = idp.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
