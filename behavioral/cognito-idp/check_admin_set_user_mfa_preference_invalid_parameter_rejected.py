"""admin-set-user-mfa-preference-invalid-parameter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-invalid-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference enabling SMS MFA for a user without a verified phone number is
    refused with InvalidParameterException and the exact message and applies nothing; after a
    verified number is added, the same call makes SMS_MFA enabled and preferred."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    username = _create_user(ctx, pool_id)

    before = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before.get("UserMFASettingList", []) == [], (
        f"expected no MFA settings on a fresh user, got {before.get('UserMFASettingList')}"
    )

    # Negative: no phone_number attribute at all on this user.
    code, message = _error(
        lambda: cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "User does not have delivery config set to turn on SMS_MFA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_bad.get("UserMFASettingList", []) == [], (
        f"expected the rejected preference to not apply, got {after_bad.get('UserMFASettingList')}"
    )
    assert after_bad.get("PreferredMfaSetting") is None, (
        f"expected no preferred MFA after rejection, got {after_bad.get('PreferredMfaSetting')}"
    )

    # Remove the one blocking condition: give the user a verified phone number.
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "phone_number", "Value": "+15555550100"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
    )

    # Positive control: the identical SMS-MFA-enable call now succeeds.
    cognito.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    after_good = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert "SMS_MFA" in after_good.get("UserMFASettingList", []), (
        f"expected SMS_MFA once the phone number is verified, got {after_good.get('UserMFASettingList')}"
    )
    assert after_good.get("PreferredMfaSetting") == "SMS_MFA", (
        f"expected SMS_MFA as the preferred method, got {after_good.get('PreferredMfaSetting')}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_user(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Sim2Real-Passw0rd!",
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    return username


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
