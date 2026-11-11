"""admin-reset-user-password-unconfirmed-user-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "admin-reset-user-password-unconfirmed-user-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminResetUserPassword on a FORCE_CHANGE_PASSWORD user is refused with NotAuthorizedException
    and the exact message and leaves the status unchanged; once the user is CONFIRMED the same call
    sets RESET_REQUIRED."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Pw!23456"
    created = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )["User"]
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    # freshly admin-created users start in FORCE_CHANGE_PASSWORD, not CONFIRMED
    assert created["UserStatus"] == "FORCE_CHANGE_PASSWORD", f"unexpected initial status {created['UserStatus']}"

    code, message = _error(lambda: idp.admin_reset_user_password(UserPoolId=pool_id, Username=username))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected_message = "User password cannot be reset in the current state."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # status must be unchanged by the rejected call
    still = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still["UserStatus"] == "FORCE_CHANGE_PASSWORD", f"status drifted to {still['UserStatus']}"

    # restore: confirm the user, then the identical call must now succeed -- this is what tells
    # "rejects unconfirmed users specifically" apart from "rejects every AdminResetUserPassword call"
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    confirmed = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert confirmed["UserStatus"] == "CONFIRMED", f"expected CONFIRMED after permanent password set, got {confirmed['UserStatus']}"

    idp.admin_reset_user_password(UserPoolId=pool_id, Username=username)
    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "RESET_REQUIRED", f"expected RESET_REQUIRED once confirmed, got {after['UserStatus']}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
