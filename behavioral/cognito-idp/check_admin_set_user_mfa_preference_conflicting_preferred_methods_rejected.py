"""admin-set-user-mfa-preference-conflicting-preferred-methods-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-conflicting-preferred-methods-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference marking two methods as PreferredMfa is refused with
    InvalidParameterException and the exact message and leaves no MFA settings, while marking only
    SMS_MFA preferred succeeds."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    username = "grace"
    password = "Sim2Real123"
    # phone_number is verified up-front so the positive control below isn't
    # blocked by a *different* validation failure (unverified SMS factor).
    _create_admin_user(
        ctx,
        pool_id,
        username,
        password,
        extra_attrs=[
            {"Name": "phone_number", "Value": "+15005550006"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )

    code, message = _error(
        lambda: cip.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "Two MFA types marked as preferred, only one is allowed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no MFA preference was applied to the user
    user = cip.admin_get_user(UserPoolId=pool_id, Username=username)
    settings_list = user.get("UserMFASettingList")
    assert not settings_list, f"expected no MFA settings after rejection, got {settings_list!r}"
    preferred = user.get("PreferredMfaSetting")
    assert preferred is None, f"expected no preferred MFA setting after rejection, got {preferred!r}"

    # positive control: a single preferred method is accepted
    cip.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    user_after = cip.admin_get_user(UserPoolId=pool_id, Username=username)
    preferred_after = user_after.get("PreferredMfaSetting")
    assert preferred_after == "SMS_MFA", f"expected SMS_MFA preferred after positive control, got {preferred_after!r}"


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
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true"},
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
