"""op-contract-adminCreateUser-weak-temp-password-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminCreateUser-weak-temp-password-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser echoes supplied UserAttributes; a TemporaryPassword below the pool policy is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    username = ctx.unique_name("sim2real-behav-user-")
    resp = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass123",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": "behav-test@example.com"}],
    )
    attrs = {a["Name"]: a["Value"] for a in resp["User"]["Attributes"]}
    assert attrs.get("email") == "behav-test@example.com", attrs

    username2 = ctx.unique_name("sim2real-behav-user2-")
    code = _client_error(
        lambda: idp.admin_create_user(
            UserPoolId=pool_id,
            Username=username2,
            TemporaryPassword="ab",  # shorter than the pool's MinimumLength(8)
            MessageAction="SUPPRESS",
        )
    )
    assert code.get("Code") == "InvalidPasswordException", f"expected InvalidPasswordException, got {code}"
    assert code.get("Message") == "Password did not conform with password policy: Password not long enough", code.get("Message")

    # effect absent: the rejected create did not leave a user behind
    usernames = {u["Username"] for u in idp.list_users(UserPoolId=pool_id)["Users"]}
    assert username2 not in usernames, f"user {username2} should not exist after rejected create"
    assert username in usernames, f"expected {username} in {usernames}"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
