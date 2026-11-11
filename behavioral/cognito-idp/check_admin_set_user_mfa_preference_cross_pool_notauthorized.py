"""admin-set-user-mfa-preference-cross-pool-notauthorized."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-cross-pool-notauthorized"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminGetUser and AdminSetUserMFAPreference for a username that exists only in another user
    pool both answer UserNotFoundException with the exact message, and ListUsers of that pool does
    not list the user."""
    idp = ctx.client("cognito-idp")

    pool_a = _create_user_pool(ctx)
    pool_b = _create_user_pool(ctx)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=pool_b, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(
        UserPoolId=pool_b, Username=username, Password=password, Permanent=True
    )

    settings = {"SMSMfaSettings": {"Enabled": False, "PreferredMfa": False}}

    # Positive control: the very same call, against the pool the user actually lives in,
    # succeeds.
    idp.admin_set_user_mfa_preference(UserPoolId=pool_b, Username=username, **settings)

    # A plain existence lookup for this username in pool_a (where it was never created)
    # is the documented "generic not-found" shape.
    lookup_code, lookup_message = _error(lambda: idp.admin_get_user(UserPoolId=pool_a, Username=username))
    assert lookup_code == "UserNotFoundException", f"AdminGetUser got {lookup_code!r}"
    expected_lookup_message = "User does not exist."
    assert lookup_message == expected_lookup_message, f"expected message {expected_lookup_message!r}, got {lookup_message!r}"

    # AdminSetUserMFAPreference for the wrong-pool username answers UserNotFoundException like
    # AdminGetUser: Admin* calls are IAM-authorized, so no user-existence masking applies.
    mfa_code, mfa_message = _error(
        lambda: idp.admin_set_user_mfa_preference(UserPoolId=pool_a, Username=username, **settings)
    )
    assert mfa_code == "UserNotFoundException", f"AdminSetUserMFAPreference got {mfa_code!r}"
    expected_mfa_message = "User does not exist."
    assert mfa_message == expected_mfa_message, f"expected message {expected_mfa_message!r}, got {mfa_message!r}"

    # Effect absence: the rejected call created no user/record in pool_a.
    users_in_a = idp.list_users(UserPoolId=pool_a)["Users"]
    names_in_a = [u["Username"] for u in users_in_a]
    assert username not in names_in_a, f"expected {username!r} absent from pool_a, got {names_in_a!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
