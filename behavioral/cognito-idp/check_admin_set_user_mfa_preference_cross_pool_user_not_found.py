"""admin-set-user-mfa-preference-cross-pool-user-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-cross-pool-user-not-found"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Test123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference and AdminGetUser scoped to a pool that does not contain the user
    answer UserNotFoundException with the exact message, and the user in its own pool keeps no MFA
    settings."""
    cognito = ctx.client("cognito-idp")
    pool_a, username = _setup_confirmed_user(ctx)
    pool_b = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-b-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_b))

    code, message = _error(
        lambda: cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_b,
            Username=username,
            SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
        )
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    expected_message = "User does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent / isolation: the user genuinely doesn't exist when scoped to pool B
    code_get, code_get_message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_b, Username=username))
    assert code_get == "UserNotFoundException", f"expected UserNotFoundException, got {code_get}"
    expected_code_get_message = "User does not exist."
    assert code_get_message == expected_code_get_message, f"expected message {expected_code_get_message!r}, got {code_get_message!r}"

    # positive control: the same call scoped to the pool that actually owns the user succeeds
    cognito.admin_set_user_mfa_preference(
        UserPoolId=pool_a,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )
    still_there = cognito.admin_get_user(UserPoolId=pool_a, Username=username)
    assert still_there["Username"] == username, f"expected {username}, got {still_there.get('Username')}"
    assert still_there.get("PreferredMfaSetting") is None, (
        f"expected no PreferredMfaSetting after disabling, got {still_there.get('PreferredMfaSetting')!r}"
    )
    assert not still_there.get("UserMFASettingList"), (
        f"expected empty UserMFASettingList after disabling, got {still_there.get('UserMFASettingList')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _setup_confirmed_user(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-a-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    return pool_id, username


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
