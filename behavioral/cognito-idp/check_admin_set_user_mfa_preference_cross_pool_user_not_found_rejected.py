"""admin-set-user-mfa-preference-cross-pool-user-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-cross-pool-user-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference for a Username that exists only in another pool answers
    UserNotFoundException with the exact message and leaves the real user's MFA settings empty,
    while the same call in the user's own pool succeeds."""
    cip = ctx.client("cognito-idp")
    pool_a = _create_pool(ctx)
    pool_b = _create_pool(ctx)
    username = "alice"
    password = "Sim2Real123"
    _create_admin_user(ctx, pool_a, username, password)

    code, message = _error(
        lambda: cip.admin_set_user_mfa_preference(
            UserPoolId=pool_b,
            Username=username,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    expected_message = "User does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the real user in pool_a has no MFA preference set
    user = cip.admin_get_user(UserPoolId=pool_a, Username=username)
    assert not user.get("UserMFASettingList"), (
        f"expected no MFA settings on {username} in pool_a, got {user.get('UserMFASettingList')}"
    )
    assert user.get("PreferredMfaSetting") is None, (
        f"expected no preferred MFA setting on {username} in pool_a, "
        f"got {user.get('PreferredMfaSetting')}"
    )

    # positive control: the same operation succeeds against the user's real pool
    cip.admin_set_user_mfa_preference(
        UserPoolId=pool_a, Username=username, SMSMfaSettings={"Enabled": False}
    )
    after = cip.admin_get_user(UserPoolId=pool_a, Username=username)
    assert after["Username"] == username, (
        f"expected {username} to remain reachable in pool_a after the positive control, "
        f"got {after.get('Username')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-pool"},
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_admin_user(ctx, pool_id, username, password, extra_attrs=None):
    cip = ctx.client("cognito-idp")
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=extra_attrs or [],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
